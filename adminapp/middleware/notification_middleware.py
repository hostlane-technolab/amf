# adminapp/middleware/notification_middleware.py
from django.contrib import messages
from django.utils.deprecation import MiddlewareMixin
from adminapp.utils.notification_helper import create_notification
import logging

logger = logging.getLogger(__name__)


class MessageToNotificationMiddleware(MiddlewareMixin):
    """
    Automatically convert Django messages to database notifications (once only)
    """
    
    MESSAGE_LEVEL_MAP = {
        25: ('success', 'create'),    # messages.SUCCESS
        20: ('info', 'other'),         # messages.INFO
        30: ('warning', 'other'),      # messages.WARNING
        40: ('danger', 'other'),       # messages.ERROR
        10: ('info', 'other'),         # messages.DEBUG
    }
    
    def process_response(self, request, response):
        """
        Process response and convert NEW messages to notifications
        """
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return response
        
        try:
            # Get message storage
            storage = messages.get_messages(request)
            
            # Check if messages have already been converted
            if hasattr(storage, '_notifications_created'):
                return response
            
            # Get all messages
            message_list = list(storage)
            
            # Create notifications for each message
            for message in message_list:
                try:
                    notification_type, action_type = self.MESSAGE_LEVEL_MAP.get(
                        message.level, 
                        ('info', 'other')
                    )
                    
                    # Create notification
                    create_notification(
                        user=request.user,
                        notification_type=notification_type,
                        action_type=action_type,
                        title=self.get_title_from_level(message.level),
                        message=str(message),
                        link_url=request.path,
                        link_text='View Details'
                    )
                except Exception as e:
                    logger.error(f"Failed to create notification: {str(e)}")
            
            # Mark that notifications have been created for these messages
            storage._notifications_created = True
            
            # Re-add messages so they still display on the page
            storage._queued_messages = message_list
            
        except Exception as e:
            logger.error(f"Notification middleware error: {str(e)}", exc_info=True)
        
        return response
    
    def get_title_from_level(self, level):
        titles = {
            25: 'Success',
            20: 'Information',
            30: 'Warning',
            40: 'Error',
            10: 'Debug',
        }
        return titles.get(level, 'Notification')