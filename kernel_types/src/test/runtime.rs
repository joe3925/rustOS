use crate::runtime::BlockOnThreadState;

#[test]
fn block_on_thread_state_tracks_single_active_owner_and_ready_flag() {
    let state = BlockOnThreadState::new();

    assert!(state.try_enter());
    assert!(!state.try_enter());

    state.mark_ready();
    assert!(state.take_ready());
    assert!(!state.take_ready());

    state.mark_ready();
    state.clear_ready();
    assert!(!state.take_ready());

    state.exit();
    assert!(state.try_enter());
}
