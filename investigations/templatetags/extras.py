from django import template

register = template.Library()

@register.filter()
def dictFirst(value):
    """Return the first found element of a dictionnary"""
    return list(value.values())[0]