import re
from functools import lru_cache
from urllib.parse import urlparse


@lru_cache
def clean_url(url):
    if not url:
        return None

    if url.startswith('github.com/'):
        url = f'https://{url}'

    try:
        parsed = urlparse(url)
    except Exception as msg:
        return None

    if parsed.hostname != 'github.com':
        return None

    path_parts = parsed.path.split('/')
    if len(path_parts) >= 3:
        new_path = '/'.join(path_parts[1:3])
        parsed = parsed._replace(path=new_path)

    # Remove .git from the end
    if parsed.path.endswith('.git/'):
        parsed = parsed._replace(path=parsed.path[:-5])
    elif parsed.path.endswith('.git'):
        parsed = parsed._replace(path=parsed.path[:-4])

    parsed = parsed._replace(scheme='https', netloc=parsed.hostname, params='', query='', fragment='')

    return parsed.geturl()

def clean_contact(contact: dict):
    name = contact.get('name')
    email = contact.get('email')

    if email and name in [None, '', 'None', 'null', 'NULL']:
        matches = re.match(r'^(.*)<([\w.+-]+@[\w-]+\.[\w.-]+)>\s*$', email)
        if matches:
            name = matches.group(1).strip()
            email = matches.group(2).strip()

    if name and email in [None, '', 'None', 'null', 'NULL']:
        matches = re.match(r'^(.*)<([\w.+-]+@[\w-]+\.[\w.-]+)>\s*$', name)
        if matches:
            name = matches.group(1).strip()
            email = matches.group(2).strip()

    contact['name'] = name
    contact['email'] = email
