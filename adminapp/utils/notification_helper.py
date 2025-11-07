from django.db.models import Q, Count
from adminapp.models import Notification


def get_unread_count(user):
    """
    Get count of unread notifications for a user
    """
    unread_notifications = Notification.objects.filter(
        is_active=True
    ).annotate(
        target_count=Count('target_users')
    ).filter(
        Q(target_users=user) | Q(target_count=0)
    ).exclude(
        read_by=user
    ).distinct()
    
    return unread_notifications.count()


def get_recent_notifications(user, limit=10):
    """
    Get recent notifications for a user
    """
    notifications = Notification.objects.filter(
        is_active=True
    ).annotate(
        target_count=Count('target_users')
    ).filter(
        Q(target_users=user) | Q(target_count=0)
    ).select_related('user').distinct().order_by('-created_at')[:limit]
    
    return notifications


def create_notification(user, notification_type, action_type, title, message, 
                       link_url=None, link_text=None, target_users=None):
    """
    Helper function to create a notification
    """
    notification = Notification.objects.create(
        user=user,
        notification_type=notification_type,
        action_type=action_type,
        title=title,
        message=message,
        link_url=link_url or '',
        link_text=link_text or ''
    )
    
    # Add target users if specified and not empty
    if target_users and len(target_users) > 0:
        notification.target_users.set(target_users)
    # If target_users is None or empty, leave M2M empty (visible to all users)
    
    return notification


def mark_notifications_read_bulk(user, notification_ids):
    """
    Mark multiple notifications as read
    """
    notifications = Notification.objects.filter(
        id__in=notification_ids,
        is_active=True
    ).exclude(read_by=user)
    
    count = 0
    for notification in notifications:
        notification.mark_as_read(user)
        count += 1
    
    return count


def delete_old_notifications(days=30):
    """
    Delete notifications older than specified days
    """
    from django.utils import timezone
    from datetime import timedelta
    
    cutoff_date = timezone.now() - timedelta(days=days)
    old_notifications = Notification.objects.filter(created_at__lt=cutoff_date)
    count = old_notifications.count()
    old_notifications.delete()
    
    return count