# SocialStack - Decentralized Social Network Protocol

A comprehensive social networking protocol built on Stacks Layer 2, providing secure user management, privacy controls, and relationship handling with Bitcoin-level security guarantees.

## Overview

SocialStack implements a robust social networking infrastructure with:

- Granular privacy controls and encryption support
- Rate-limiting and batch processing optimization
- Relationship management (friendships, blocking)
- Activity tracking and user status management
- Scalable data structures optimized for Layer 2

## Features

### User Management

- Profile creation and updates
- Status tracking (Active, Deactivated, Suspended)
- Activity monitoring
- Last seen tracking
- Login recording
- Profile metadata support
- Optional encryption key management
- Profile image support

### Privacy Controls

- Granular visibility settings for:
  - Friend lists
  - User status
  - Profile metadata
  - Last seen status
  - Profile images
- Encryption toggle for enhanced security
- Privacy settings are individually configurable

### Rate Limiting

- Daily action limits:
  - 100 total actions per day
  - 20 friend requests per day
  - 24 status updates per day
- Automatic reset after 24 hours
- Protection against platform abuse

### Batch Processing

- Dynamic batch size optimization
- Configurable batch sizes (10-100 items)
- Automatic batch expiry (1 hour)
- Performance optimization for bulk operations

### Relationship Management

- Friendship states:
  - Pending
  - Active
  - Blocked
- User blocking functionality
- Relationship status tracking

## Technical Details

### Data Structures

#### Users Map

```clarity
{
    name: (string-ascii 64),
    status: uint,
    timestamp: uint,
    metadata: (optional (string-utf8 256)),
    deactivation-time: (optional uint),
    encryption-key: (optional (buff 32)),
    profile-image: (optional (string-utf8 256))
}
```

#### Privacy Settings

```clarity
{
    friend-list-visible: bool,
    status-visible: bool,
    metadata-visible: bool,
    last-seen-visible: bool,
    profile-image-visible: bool,
    encryption-enabled: bool,
    last-updated: uint
}
```

#### Rate Limiting

```clarity
{
    daily-actions: uint,
    friend-requests: uint,
    status-updates: uint,
    last-reset: uint
}
```

### Error Handling

| Code | Description    |
| ---- | -------------- |
| 100  | Not Found      |
| 101  | Already Exists |
| 102  | Unauthorized   |
| 103  | Invalid Input  |
| 104  | Blocked        |
| 105  | Deactivated    |
| 106  | Rate Limited   |
| 107  | Batch Full     |
| 108  | Batch Expired  |

## Public Functions

### Profile Management

- `update-user-profile`: Update user profile information
- `update-advanced-privacy-settings`: Configure privacy settings
- `record-login`: Record user login activity

### Batch Processing

- `optimize-batch-size`: Automatically optimize batch processing
- `set-batch-size`: Manually configure batch size

## Security Features

### Rate Limiting

- Prevents abuse through daily action limits
- Automatic reset mechanism
- Separate limits for different action types

### Privacy Controls

- Granular visibility settings
- Optional encryption support
- Activity tracking protection

### Access Control

- Principal-based authentication
- Status-based access control
- Relationship-based permissions

## Performance Optimization

### Batch Processing

- Dynamic batch size adjustment
- Automatic optimization based on usage patterns
- Configurable limits and expiry

### Data Structure Optimization

- Efficient map structures
- Optional fields for flexibility
- Optimized for Layer 2 operations

## Best Practices

### Rate Limiting

1. Monitor daily action counts
2. Implement gradual backoff
3. Reset counters at appropriate intervals

### Privacy

1. Default to restrictive settings
2. Validate all privacy changes
3. Maintain audit logs

### Batch Processing

1. Start with recommended batch sizes
2. Monitor optimization patterns
3. Adjust based on network conditions
