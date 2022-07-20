from django import template

register = template.Library()

@register.filter()
def dictFirst(value):
    """Return the first found element of a dictionnary"""
    try:
        return list(value.values())[0]
    except:
        return [{}]