  ##  URL Feature Extraction  ##
# Below are the funtions for extracting each feature from the given URL #

# Required Librabries #

from urllib.parse import urlparse,urlencode
import urllib.parse
import ipaddress
import re
import whois
import re
from bs4 import BeautifulSoup
import urllib
import urllib.request
from datetime import datetime

# Address Bar Based Features #

# 1. IP Address in the URL #

def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'  # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        '[0-9a-fA-F]{7}', url)  # Ipv6
    if match:
        return 1
    else:
        return 0

# 2. Depth of URL #

def getDepth(url):
  s = urlparse(url).path.split('/')
  depth = 0
  for j in range(len(s)):
    if len(s[j]) != 0:
      depth = depth+1
  return depth

# 3. Redirection "//" in URL #

def redirection(url):
    if '//' in url[7:]:
        return 1
    else:
        return 0
    
# 4. "http/https" in Domain name #
    
def httpDomain(url):
  domain = urlparse(url).netloc
  if 'https' in domain:
    return 1
  else:
    return 0

# 5. Using URL Shortening Services “TinyURL #
  
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

def tinyURL(url):
    match = re.search(shortening_services, url)
    if match:
        return 1
    else:
        return 0
    
# 6. Length of URL #
    
def getLength(url):          
  return len(url)

# 7. Function to count numeric characters #

def NumericCharCount(str):
    # Initializing count variable to 0
    count = 0

    # Creating a set of numeric characters
    numeric = set("0123456789")

    # Loop to traverse the num
    # in the given string
    for num in str:

        # If numeric character is present
        # in set numeric
        if num in numeric:
            count = count + 1

    return count

# 8. Function to count english letters #

def EnglishLetterCount(str):
    # Initializing count variable to 0
    count = 0

    # Creating a set of english letters
    engletter = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

    # Loop to traverse the num
    # in the given string
    for num in str:

        # If english letter is present
        # in set engletter
        if num in engletter:
            count = count + 1

    return count

# 9. Function to count Special Characters #

def SpecialCharCount(str):
    # Initializing count variable to 0
    count = 0

    # Creating a set of special characters
    specialchar = set("!#$%&'()*+,-./:;<=>?@[\]^_`{|}~\"")

    # Loop to traverse the num
    # in the given string
    for num in str:

        # If special character is present
        # in set specialchar
        if num in specialchar:
            count = count + 1

    return count

# 10. Function to calculate ratio of digits to alphabets #

def DigitAlphabetRatio(str):

    digit = 0
    numeric = set("0123456789")

    for num in str:
        if num in numeric:
            digit = digit + 1

    alphabet = 0
    engletter = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
    flag = -1
    for num in str:
        if num in engletter:
            alphabet = alphabet + 1

    if alphabet != 0:
        ratio = digit/alphabet
        return ratio

    else:
        return flag

# 11. Count at (@) symbol at base url #

def count_at(base_url):
     return base_url.count('@')
 
# 12. Count comma (,) symbol at base url #

def count_comma(base_url):
     return base_url.count(',')

# 13. Count dollar ($) symbol at base url #

def count_dollar(base_url):
     return base_url.count('$')

# 14. Having semicolumn (;) symbol at base url #

def count_semicolumn(url):
     return url.count(';')

# 15. Count (space, %20) symbol at base url #

def count_space(base_url):
     return base_url.count(' ')+base_url.count('%20')

# 16. Count and (&) symbol at base url #

def count_and(base_url):
     return base_url.count('&')

# 17. Count slash (/) symbol at full url #

def count_slash(full_url):
    return full_url.count('/')

# 18. Count equal (=) symbol at base url #

def count_equal(base_url):
    return base_url.count('=')

# 19. Count percentage (%) symbol at base url #

def count_percentage(base_url):
    return base_url.count('%')

# 20. Count exclamation (?) symbol at base url #

def count_exclamation(base_url):
    return base_url.count('?')

# 21. Count underscore (_) symbol at base url #

def count_underscore(base_url):
    return base_url.count('_')

# 22. Count dash (-) symbol at base url #

def count_hyphens(base_url):
    return base_url.count('-')

# 23. Count number of dots in hostname #

def count_dots(hostname):
    return hostname.count('.')

# 24. Count number of colon (:) symbol #

def count_colon(url):
    return url.count(':')

# 25. Count number of stars (*) symbol #

def count_star(url):
    return url.count('*')

# 26. Count number of OR (|) symbol (Srinivasa Rao'19)

def count_or(url):
    return url.count('|')






# Domain Based Features #

# 1. DNS Record #
    
def hasDNSRecord(domain):
    try:
        whois_info = whois.whois(domain)
        if whois_info:
            return 0  
        else:
            return 1  
    except whois.parser.PywhoisError:
        return 1  # (Error occurred or no record found)

# 2. Age of Domain #
    
def domainAge(domain_name):
    try:
        # Get WHOIS information for the domain
        domain_info = whois.whois(domain_name)

        # Extract creation and expiration dates
        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date

        # Check if creation_date and expiration_date are valid datetime objects
        if (isinstance(creation_date, list)):
            creation_date = creation_date[0]
        if (isinstance(expiration_date, list)):
            expiration_date = expiration_date[0]

        # Calculate domain age
        current_date = datetime.now()
        age_of_domain = (current_date - creation_date).days

        # Determine if the domain age is less than 1 year
        if age_of_domain < 365:  # Less than 1 year
            return 1  
        else:
            return 0  

    except Exception as e:
        print("Error:", e)
        return 1  
    
# 3.  #