from urllib.parse import urlparse

import markdown
from django import template
from django.utils.safestring import mark_safe

register = template.Library()

@register.filter(name='render_markdown')
def render_markdown(text):
    if not text:
        return ""
    return mark_safe(markdown.markdown(text))


@register.filter(name='split')
def split(value, key):
    return [x.strip() for x in value.split(key)]


@register.filter(name='count')
def count(value):
    return len(value.split(','))


@register.filter(name='getpath')
def getpath(value):
    parsed_url = urlparse(value)
    if parsed_url.query:
        return parsed_url.path + '?' + parsed_url.query
    else:
        return parsed_url.path


@register.filter(name='none_or_never')
def none_or_never(value):
    return 'Never' if value is None else value


# https://stackoverflow.com/a/32801096
@register.filter
def next(some_list, current_index):
    """
    Returns the next element of the list using the current index if it exists.
    Otherwise returns an empty string.
    """
    try:
        return some_list[int(current_index) + 1] # access the next element
    except:
        return '' # return empty string in case of exception

@register.filter
def previous(some_list, current_index):
    """
    Returns the previous element of the list using the current index if it exists.
    Otherwise returns an empty string.
    """
    try:
        return some_list[int(current_index) - 1] # access the previous element
    except:
        return '' # return empty string in case of exception


from reNgine.common_func import categorize_secret_type as _categorize_secret_type


@register.filter(name='categorize_secret')
def categorize_secret(value):
    """Return (category_name, color_key) tuple for a human-readable secret label.

    Usage in template: {% with cat=leak.secret_type|categorize_secret %}{{ cat.0 }}{% endwith %}
    """
    return _categorize_secret_type(value)
