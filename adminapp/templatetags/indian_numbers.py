from django import template

register = template.Library()

@register.filter(name='indian_comma')
def indian_comma(value):
    """
    Converts a number to Indian comma format (e.g., 12,34,567.89)
    """
    try:
        value = float(value)
        
        # Split into integer and decimal parts
        integer_part = int(value)
        decimal_part = value - integer_part
        
        # Convert integer part to string
        s = str(integer_part)
        
        # Handle negative numbers
        if s.startswith('-'):
            sign = '-'
            s = s[1:]
        else:
            sign = ''
        
        # Format according to Indian numbering system
        if len(s) <= 3:
            result = s
        else:
            last_three = s[-3:]
            remaining = s[:-3]
            
            # Add commas every 2 digits for the remaining part (from right to left)
            formatted_remaining = ''
            for i, digit in enumerate(reversed(remaining)):
                if i > 0 and i % 2 == 0:
                    formatted_remaining = ',' + formatted_remaining
                formatted_remaining = digit + formatted_remaining
            
            result = formatted_remaining + ',' + last_three
        
        # Add decimal part - get digits after decimal point
        decimal_str = f"{decimal_part:.2f}"[2:]
        
        return f"{sign}{result}.{decimal_str}"
        
    except (ValueError, TypeError):
        return value