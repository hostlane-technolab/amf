# adminapp/message_storage.py
from django.contrib.messages.storage.session import SessionStorage
from adminapp.utils.notification_helper import create_notification


class NotificationStorage(SessionStorage):
    """
    Custom message storage that creates database notifications
    """
    
    MESSAGE_LEVEL_MAP = {
        25: ('success', 'create'),
        20: ('info', 'other'),
        30: ('warning', 'other'),
        40: ('danger', 'other'),
        10: ('info', 'other'),
    }
    
    def add(self, level, message, extra_tags=''):
        """
        Override add to create notification when message is added
        """
        # Call parent to add message normally
        result = super().add(level, message, extra_tags)
        
        # Create notification
        if hasattr(self.request, 'user') and self.request.user.is_authenticated:
            try:
                notification_type, action_type = self.MESSAGE_LEVEL_MAP.get(
                    level, 
                    ('info', 'other')
                )
                
                titles = {
                    25: 'Success',
                    20: 'Information',
                    30: 'Warning',
                    40: 'Error',
                    10: 'Debug',
                }
                
                create_notification(
                    user=self.request.user,
                    notification_type=notification_type,
                    action_type=action_type,
                    title=titles.get(level, 'Notification'),
                    message=str(message),
                    link_url=self.request.path,
                    link_text='View Details'
                )
            except Exception as e:
                pass  # Don't break if notification fails
        
        return result