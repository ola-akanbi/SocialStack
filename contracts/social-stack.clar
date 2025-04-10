;; Title: SocialStack - Decentralized Social Network Protocol

;; Summary:
;; A comprehensive social networking protocol built on Stacks Layer 2,
;; providing secure user management, privacy controls, and relationship handling
;; with Bitcoin-level security guarantees.

;; Description:
;; SocialStack implements a robust social networking infrastructure with:
;; - Granular privacy controls and encryption support
;; - Rate-limiting and batch processing optimization
;; - Relationship management (friendships, blocking)
;; - Activity tracking and user status management
;; - Scalable data structures optimized for Layer 2
;; All operations are designed for maximum efficiency and minimal chain bloat.

;; Constants
;; =========

;; Error codes - Standardized error handling
(define-constant ERR_NOT_FOUND (err u100))
(define-constant ERR_ALREADY_EXISTS (err u101))
(define-constant ERR_UNAUTHORIZED (err u102))
(define-constant ERR_INVALID_INPUT (err u103))
(define-constant ERR_BLOCKED (err u104))
(define-constant ERR_DEACTIVATED (err u105))
(define-constant ERR_RATE_LIMITED (err u106))
(define-constant ERR_BATCH_FULL (err u107))
(define-constant ERR_BATCH_EXPIRED (err u108))

;; Status Constants - User account states
(define-constant STATUS_DEACTIVATED u0)
(define-constant STATUS_ACTIVE u1)
(define-constant STATUS_SUSPENDED u2)

;; Relationship Constants - Friendship states
(define-constant FRIENDSHIP_PENDING u0)
(define-constant FRIENDSHIP_ACTIVE u1)
(define-constant FRIENDSHIP_BLOCKED u2)

;; Rate Limiting Constants - Platform protection
(define-constant MAX_ACTIONS_PER_DAY u100)
(define-constant MAX_FRIEND_REQUESTS_PER_DAY u20)
(define-constant MAX_STATUS_UPDATES_PER_DAY u24)
(define-constant RATE_LIMIT_RESET_PERIOD u86400) ;; 24 hours in seconds

;; Batch Processing Constants - Optimization parameters
(define-constant MIN_BATCH_SIZE u10)
(define-constant MAX_BATCH_SIZE u100)
(define-constant BATCH_EXPIRY_PERIOD u3600) ;; 1 hour in seconds

;; Data Maps
;; =========

;; Users - Core user data storage
(define-map Users 
    principal 
    {
        name: (string-ascii 64),
        status: uint,
        timestamp: uint,
        metadata: (optional (string-utf8 256)),
        deactivation-time: (optional uint),
        encryption-key: (optional (buff 32)),
        profile-image: (optional (string-utf8 256))
    }
)

;; UserPrivacy - Privacy settings storage
(define-map UserPrivacy
    principal
    {
        friend-list-visible: bool,
        status-visible: bool,
        metadata-visible: bool,
        last-seen-visible: bool,
        profile-image-visible: bool,
        encryption-enabled: bool,
        last-updated: uint
    }
)

;; RateLimits - Rate limiting data
(define-map RateLimits
    principal
    {
        daily-actions: uint,
        friend-requests: uint,
        status-updates: uint,
        last-reset: uint
    }
)

;; UserBatches - Batch processing management
(define-map UserBatches
    principal
    {
        message-counter: uint,
        last-batch-timestamp: uint,
        batch-size: uint,
        current-batch-items: uint,
        total-batches: uint
    }
)

;; UserActivity - User activity tracking
(define-map UserActivity
    principal
    {
        last-seen: uint,
        login-count: uint,
        total-actions: uint,
        last-action: uint
    }
)

;; Friendships - Relationship management
(define-map Friendships
    {
        user1: principal,
        user2: principal
    }
    {
        status: uint
    }
)

;; BlockedUsers - User blocking management
(define-map BlockedUsers
    {
        blocker: principal,
        blocked: principal
    }
    {
        timestamp: uint
    }
)

;; Private Functions
;; ================

;; Rate limit checker
(define-private (check-rate-limit (user principal) (action-type uint))
    (let
        (
            (rate-data (default-to 
                {
                    daily-actions: u0,
                    friend-requests: u0,
                    status-updates: u0,
                    last-reset: stacks-block-height
                }
                (map-get? RateLimits user)
            ))
            (current-time stacks-block-height)
            (should-reset (> (- current-time (get last-reset rate-data)) RATE_LIMIT_RESET_PERIOD))
        )
        (if should-reset
            (begin
                (map-set RateLimits user
                    {
                        daily-actions: u1,
                        friend-requests: (if (is-eq action-type u1) u1 u0),
                        status-updates: (if (is-eq action-type u2) u1 u0),
                        last-reset: current-time
                    }
                )
                true
            )
            (and
                (< (get daily-actions rate-data) MAX_ACTIONS_PER_DAY)
                (or 
                    (not (is-eq action-type u1))
                    (< (get friend-requests rate-data) MAX_FRIEND_REQUESTS_PER_DAY)
                )
                (or
                    (not (is-eq action-type u2))
                    (< (get status-updates rate-data) MAX_STATUS_UPDATES_PER_DAY)
                )
            )
        )
    )
)