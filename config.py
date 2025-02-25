# nginx access.log, modify it if your nginx log path is different
nginx_log_path = '/var/log/nginx/access.log'

# iptables rules path, modify it if your iptables rules path is different
iptables_rules_path = '/etc/iptables/rules.v4'

# Define a dictionary mapping routes (URL paths) to a list of allowed HTTP request methods
route_method_rules = {
    # some examples:
    '/static/css/index.css': ['GET'],
    '/static/js/index.js': ['GET'],
    '/static/images/logo.ico': ['GET'],
    '/robots.txt': ['GET'],
    '/sitemap.xml': ['GET'],
    # you can add more route and method rules here
}

# Define a list of allowed IP addresses
white_list = []

# match pattern for nginx access.log
nginx_log_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?"(.*?)"'

# the threshold for the number of illegal requests
illegal_number_threshold = 10

# the threshold for the rate of illegal requests
illegal_rate_threshold = 0.9
