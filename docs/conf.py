import datetime

__author__ = 'Szilárd Pfeiffer'
__title__ = 'CryptoDataHub'


extensions = []
templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'

project = __title__
copyright = f'{datetime.datetime.now().year}, {__author__}'

exclude_patterns = ['_build']

html_theme = 'alabaster'
html_sidebars = {
    '**': [
        'about.html',
        'navigation.html',
        'relations.html',
        'searchbox.html',
        'donate.html',
    ]
}
html_theme_options = {
    'description': 'Cryptography-related data repository with Python wrapper',
    'fixed_sidebar': True,
    'collapse_navigation': False,
}
