/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */

// Structs copied from edk2

///
/// EFI_RUNTIME_EVENT_ENTRY
///
typedef LIST_ENTRY EFI_LIST_ENTRY;
struct _EFI_RUNTIME_EVENT_ENTRY {
  ///
  /// The same as Type passed into CreateEvent().
  ///
  UINT32              Type;
  ///
  /// The same as NotifyTpl passed into CreateEvent().
  ///
  EFI_TPL             NotifyTpl;
  ///
  /// The same as NotifyFunction passed into CreateEvent().
  ///
  EFI_EVENT_NOTIFY    NotifyFunction;
  ///
  /// The same as NotifyContext passed into CreateEvent().
  ///
  VOID                *NotifyContext;
  ///
  /// The EFI_EVENT returned by CreateEvent(). Event must be in runtime memory.
  ///
  EFI_EVENT           *Event;
  ///
  /// Entry for this node in the
  /// EFI_RUNTIME_ARCHITECTURE_PROTOCOL.EventHead list.
  ///
  EFI_LIST_ENTRY      Link;
};
typedef struct _EFI_RUNTIME_EVENT_ENTRY EFI_RUNTIME_EVENT_ENTRY;

///
/// Timer event information
///
typedef struct {
  LIST_ENTRY    Link;
  UINT64        TriggerTime;
  UINT64        Period;
} TIMER_EVENT_INFO;

#define EVENT_SIGNATURE  SIGNATURE_32('e','v','n','t')
typedef struct {
  UINTN                      Signature;
  UINT32                     Type;
  UINT32                     SignalCount;
  ///
  /// Entry if the event is registered to be signalled
  ///
  LIST_ENTRY                 SignalLink;
  ///
  /// Notification information for this event
  ///
  EFI_TPL                    NotifyTpl;
  EFI_EVENT_NOTIFY           NotifyFunction;
  VOID                       *NotifyContext;
  EFI_GUID                   EventGroup;
  LIST_ENTRY                 NotifyLink;
  UINT8                      ExFlag;
  ///
  /// A list of all runtime events
  ///
  EFI_RUNTIME_EVENT_ENTRY    RuntimeData;
  TIMER_EVENT_INFO           Timer;
} IEVENT;



/**

  Find and initialize gEfiTimerList
    - gEfiTimerList: Doubly linked list head of timer events
    - This will be used in TriggerAllTimerEvents()

**/
LIST_ENTRY *gEfiTimerList = NULL;
EFI_STATUS
EFIAPI
InitPseudoTimer(
    )
{
  EFI_STATUS Status = EFI_SUCCESS;

  EFI_EVENT DummyEvent;
  Status = gBS->CreateEvent(
      EVT_TIMER,
      TPL_CALLBACK,
      NULL,
      NULL,
      &DummyEvent
      );
  if(Status!=EFI_SUCCESS) {
    Print(L"CreateEvent(EVT_TIMER) failed %r\n", Status);
    return Status;
  }

  // Add dummy event to the mEfiTimerList
  Status = gBS->SetTimer(
      DummyEvent,
      TimerRelative,
      0
      );
  if(Status!=EFI_SUCCESS) {
    Print(L"SetTimer failed %r\n", Status);
    return Status;
  }

  // Follow dummy event blink to locate mEfiTimerList
	IEVENT *evt = (IEVENT*)DummyEvent;
  while(evt->Signature == EVENT_SIGNATURE) {
    evt = CR(evt->Timer.Link.BackLink, IEVENT, Timer.Link);
  }
  gEfiTimerList = &evt->Timer.Link;

  return Status;
}



/**

  Trigger all timer events
   - Since timer interrupts are no longer triggered, we have to
     trigger them manually

**/
VOID
EFIAPI
TriggerAllTimerEvents(
    )
{
  IEVENT *evt = CR(gEfiTimerList->ForwardLink, IEVENT, Timer.Link);

  while(evt->Signature == EVENT_SIGNATURE) {
    RemoveEntryList(&evt->Timer.Link);

    EFI_TPL OrigTpl;
    OrigTpl = gBS->RaiseTPL(TPL_HIGH_LEVEL-1);

    // Add the event to the gEventQueue
    gBS->SignalEvent(evt);

    // Events in the gEventQueue is triggered by RestoreTPL
    gBS->RestoreTPL(OrigTpl);

    if(evt->Timer.Period != 0) {
      // Insert the event back to the gEfiTimerList
      evt->Timer.Link.ForwardLink->BackLink = &evt->Timer.Link;
      evt->Timer.Link.BackLink->ForwardLink = &evt->Timer.Link;
    }
    evt = CR(evt->Timer.Link.ForwardLink, IEVENT, Timer.Link);
  }
}



/**

  Use this to wait for async events (e.g., after sending http request)
   - Restore TPL to the lowest value so that the
     non-timer events also can be triggered

**/
VOID
EFIAPI
WaitForCompletion(
    )
{
  // Set TPL to the lowest
  gBS->RestoreTPL(TPL_APPLICATION);
  TriggerAllTimerEvents();
}
