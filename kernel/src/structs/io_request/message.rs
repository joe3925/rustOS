use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use crate::executable::program::{Message, ProgramHandle, QueueHandle};
use crate::object_manager::behavior::CONFIGURE_BIT;
use crate::object_manager::{InterfaceMask, Object, ObjectPayload};
use kernel_sync::{AsyncRecvError, WaitRegistration};
use kernel_types::object_manager::ObjectTag;
use spin::Mutex;

use super::{IO_STATUS_BUFFER_TOO_SMALL, IO_STATUS_CANCELLED, IoRequestOutput};
use crate::memory::io_buffer::OwnedIoBuffer;
use kernel_types::dma::FromDevice;

struct DeliveryInner {
    completion: Option<IoRequestOutput>,
    waiters: Vec<Waker>,
}

pub struct MessageDelivery {
    inner: Mutex<DeliveryInner>,
}

impl core::fmt::Debug for MessageDelivery {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("MessageDelivery")
            .finish_non_exhaustive()
    }
}

impl MessageDelivery {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(DeliveryInner {
                completion: None,
                waiters: Vec::new(),
            }),
        })
    }

    pub fn complete(&self, output: IoRequestOutput) -> bool {
        let waiters = {
            let mut inner = self.inner.lock();
            if inner.completion.is_some() {
                return false;
            }
            inner.completion = Some(output);
            core::mem::take(&mut inner.waiters)
        };
        for waiter in waiters {
            waiter.wake();
        }
        true
    }

    fn poll_completion(&self, cx: &mut Context<'_>) -> Poll<IoRequestOutput> {
        let mut inner = self.inner.lock();
        if let Some(output) = inner.completion {
            return Poll::Ready(output);
        }
        if inner
            .waiters
            .iter()
            .all(|waiter| !waiter.will_wake(cx.waker()))
        {
            inner.waiters.push(cx.waker().clone());
        }
        Poll::Pending
    }
}

pub(crate) struct MessageSendFuture {
    target: ProgramHandle,
    message: Option<Message>,
    delivery: Arc<MessageDelivery>,
}

impl MessageSendFuture {
    pub fn new(target: ProgramHandle, message: Message) -> Self {
        Self {
            target,
            message: Some(message),
            delivery: MessageDelivery::new(),
        }
    }
}

impl Future for MessageSendFuture {
    type Output = IoRequestOutput;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(mut message) = self.message.take() {
            let erased: Arc<dyn core::any::Any + Send + Sync> = self.delivery.clone();
            let control = Object::new(ObjectTag::Generic, ObjectPayload::Generic(erased));
            let handle = self.target.read().create_user_handle_with_interface(
                control,
                InterfaceMask::from_raw(ObjectTag::Generic, CONFIGURE_BIT),
            );
            if handle == 0 {
                return Poll::Ready(IoRequestOutput::error(IO_STATUS_CANCELLED));
            }
            message.delivery = Some(handle);
            self.target.write().receive_message(message);
        }

        self.delivery.poll_completion(cx)
    }
}

impl Drop for MessageSendFuture {
    fn drop(&mut self) {
        let _ = self
            .delivery
            .complete(IoRequestOutput::error(IO_STATUS_CANCELLED));
    }
}

pub(crate) struct MqReceiveFuture {
    pub queue: QueueHandle,
    pub buffer: Option<OwnedIoBuffer<FromDevice>>,
    pub registration: WaitRegistration,
}

impl Future for MqReceiveFuture {
    type Output = IoRequestOutput;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let message = match this.queue.poll_message(&this.registration, cx) {
            Poll::Ready(Ok(message)) => message,
            Poll::Ready(Err(AsyncRecvError::Closed)) => {
                return Poll::Ready(IoRequestOutput::error(IO_STATUS_CANCELLED));
            }
            Poll::Ready(Err(AsyncRecvError::Empty)) | Poll::Pending => return Poll::Pending,
        };

        let message_size = core::mem::size_of::<Message>();
        if this
            .buffer
            .as_ref()
            .is_none_or(|buffer| buffer.len() < message_size)
        {
            return Poll::Ready(IoRequestOutput::error(IO_STATUS_BUFFER_TOO_SMALL));
        }

        let bytes = unsafe {
            core::slice::from_raw_parts(&message as *const Message as *const u8, message_size)
        };
        let mut buffer = this.buffer.take().unwrap();
        let result = buffer.copy_from_slice(bytes);
        drop(buffer);
        Poll::Ready(match result {
            Ok(()) => IoRequestOutput::success(message_size as u64, 0),
            Err(_) => IoRequestOutput::error(IO_STATUS_BUFFER_TOO_SMALL),
        })
    }
}
