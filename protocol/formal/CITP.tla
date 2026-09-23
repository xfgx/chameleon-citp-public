----------------------------- MODULE CITP -----------------------------
EXTENDS Naturals, FiniteSets

CONSTANTS Clients, StreamIDs, MaxNonce, MaxStreams, MaxPending, MaxCache

SessionStates == {"CLOSED", "HANDSHAKE", "ESTABLISHED", "FAILED"}
StreamStates  == {"ABSENT", "OPENING", "OPEN", "CLOSED"}

VARIABLES session, authenticated, sendNonce, recvNonce, streams,
          pendingHandlers, cacheSize, policyApproved

vars == <<session, authenticated, sendNonce, recvNonce, streams,
          pendingHandlers, cacheSize, policyApproved>>

Init ==
  /\ session = "CLOSED"
  /\ authenticated = FALSE
  /\ sendNonce = 0
  /\ recvNonce = 0
  /\ streams = [s \in StreamIDs |-> "ABSENT"]
  /\ pendingHandlers = 0
  /\ cacheSize = 0
  /\ policyApproved = [s \in StreamIDs |-> FALSE]

StartHandshake ==
  /\ session = "CLOSED"
  /\ session' = "HANDSHAKE"
  /\ UNCHANGED <<authenticated, sendNonce, recvNonce, streams,
                 pendingHandlers, cacheSize, policyApproved>>

Authenticate ==
  /\ session = "HANDSHAKE"
  /\ session' = "ESTABLISHED"
  /\ authenticated' = TRUE
  /\ UNCHANGED <<sendNonce, recvNonce, streams, pendingHandlers,
                 cacheSize, policyApproved>>

RejectHandshake ==
  /\ session = "HANDSHAKE"
  /\ session' = "FAILED"
  /\ authenticated' = FALSE
  /\ UNCHANGED <<sendNonce, recvNonce, streams, pendingHandlers,
                 cacheSize, policyApproved>>

ApproveOpen(s) ==
  /\ session = "ESTABLISHED"
  /\ authenticated
  /\ streams[s] = "ABSENT"
  /\ Cardinality({x \in StreamIDs : streams[x] \in {"OPENING", "OPEN"}}) < MaxStreams
  /\ pendingHandlers < MaxPending
  /\ streams' = [streams EXCEPT ![s] = "OPENING"]
  /\ policyApproved' = [policyApproved EXCEPT ![s] = TRUE]
  /\ pendingHandlers' = pendingHandlers + 1
  /\ UNCHANGED <<session, authenticated, sendNonce, recvNonce, cacheSize>>

OpenComplete(s) ==
  /\ streams[s] = "OPENING"
  /\ policyApproved[s]
  /\ streams' = [streams EXCEPT ![s] = "OPEN"]
  /\ pendingHandlers' = pendingHandlers - 1
  /\ UNCHANGED <<session, authenticated, sendNonce, recvNonce,
                 cacheSize, policyApproved>>

RejectOpen(s) ==
  /\ streams[s] = "OPENING"
  /\ streams' = [streams EXCEPT ![s] = "CLOSED"]
  /\ policyApproved' = [policyApproved EXCEPT ![s] = FALSE]
  /\ pendingHandlers' = pendingHandlers - 1
  /\ UNCHANGED <<session, authenticated, sendNonce, recvNonce, cacheSize>>

CloseStream(s) ==
  /\ streams[s] \in {"OPENING", "OPEN"}
  /\ streams' = [streams EXCEPT ![s] = "CLOSED"]
  /\ policyApproved' = [policyApproved EXCEPT ![s] = FALSE]
  /\ UNCHANGED <<session, authenticated, sendNonce, recvNonce,
                 pendingHandlers, cacheSize>>

SendFrame ==
  /\ session = "ESTABLISHED"
  /\ sendNonce < MaxNonce
  /\ sendNonce' = sendNonce + 1
  /\ UNCHANGED <<session, authenticated, recvNonce, streams,
                 pendingHandlers, cacheSize, policyApproved>>

ReceiveFrame ==
  /\ session = "ESTABLISHED"
  /\ recvNonce < MaxNonce
  /\ recvNonce' = recvNonce + 1
  /\ UNCHANGED <<session, authenticated, sendNonce, streams,
                 pendingHandlers, cacheSize, policyApproved>>

CacheResolution ==
  /\ session = "ESTABLISHED"
  /\ cacheSize < MaxCache
  /\ cacheSize' = cacheSize + 1
  /\ UNCHANGED <<session, authenticated, sendNonce, recvNonce, streams,
                 pendingHandlers, policyApproved>>

FailSession ==
  /\ session \in {"HANDSHAKE", "ESTABLISHED"}
  /\ session' = "FAILED"
  /\ streams' = [s \in StreamIDs |-> "CLOSED"]
  /\ pendingHandlers' = 0
  /\ policyApproved' = [s \in StreamIDs |-> FALSE]
  /\ UNCHANGED <<authenticated, sendNonce, recvNonce, cacheSize>>

Next ==
  \/ StartHandshake
  \/ Authenticate
  \/ RejectHandshake
  \/ SendFrame
  \/ ReceiveFrame
  \/ CacheResolution
  \/ FailSession
  \/ \E s \in StreamIDs:
       ApproveOpen(s) \/ OpenComplete(s) \/ RejectOpen(s) \/ CloseStream(s)

TypeOK ==
  /\ session \in SessionStates
  /\ authenticated \in BOOLEAN
  /\ sendNonce \in 0..MaxNonce
  /\ recvNonce \in 0..MaxNonce
  /\ streams \in [StreamIDs -> StreamStates]
  /\ policyApproved \in [StreamIDs -> BOOLEAN]
  /\ pendingHandlers \in 0..MaxPending
  /\ cacheSize \in 0..MaxCache

OnlyAuthenticatedEstablished == session = "ESTABLISHED" => authenticated
OpenRequiresPolicy == \A s \in StreamIDs: streams[s] = "OPEN" => policyApproved[s]
StreamLimit == Cardinality({s \in StreamIDs : streams[s] \in {"OPENING", "OPEN"}}) <= MaxStreams
FailedHasNoStreams == session = "FAILED" => \A s \in StreamIDs: streams[s] \notin {"OPENING", "OPEN"}

Spec == Init /\ [][Next]_vars
=============================================================================
