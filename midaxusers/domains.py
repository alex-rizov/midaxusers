from .models import domain_separator, ManagerTypesEnum, User
from flask import abort
from sqlalchemy import or_

def domain_cleanup(domain):
    domain = domain.casefold()
    domainlevels = domain.split(domain_separator)
    current_domain_depth = ''    
        
    current_domain_depth = domainlevels[0]    

    if current_domain_depth == '*':
        current_domain_depth = ''
        
    for domainlevel in domainlevels[1:]: 
        if domainlevel is not None and len(domainlevel) > 0:
            current_domain_depth += domain_separator 
            current_domain_depth += '{}'.format(domainlevel)
    
    return current_domain_depth
    
def verify_domain_rights(loggeduser, targetuser = None, targetdomain = None):
    if loggeduser.domain == '*':
        return True
    
    if targetdomain is None:   
        if targetuser is None:
           abort(404)

        if targetuser.domain is None:
            abort(404)        

        targetdomain = targetuser.domain

    targetdomain = targetdomain.casefold()

    userdomainlevels = loggeduser.domain.split(domain_separator)
    targetdomainlevels  = targetdomain.split(domain_separator)
    zipped_tuples = zip(userdomainlevels, targetdomainlevels)
    for user_element, target_element in zipped_tuples:
        if user_element != target_element:
            abort(403)
            
    if len(userdomainlevels) > len(targetdomainlevels):
        abort(403)

    return True

def can_user_see_user(loggeduser, targetuser):
    try:
        return verify_domain_rights(loggeduser, targetuser = targetuser)
    except:
        return False

def verify_user_manage_rights(loggeduser, targetuser = None, targetdomain = None, self_update_force_allowed = False):
    if loggeduser != None and loggeduser == targetuser and self_update_force_allowed == True:
        return True

    if loggeduser.user_manage_rights == ManagerTypesEnum.none:
        abort(403)

    if loggeduser.domain == '*':
        return True

    if targetdomain is None:   
        if targetuser is None:
           abort(404)

        if targetuser.domain is None:
            abort(404)        

        targetdomain = targetuser.domain

    targetdomain = targetdomain.casefold()

    userdomainlevels = loggeduser.domain.split(domain_separator)
    targetdomainlevels  = targetdomain.split(domain_separator)
    zipped_tuples = zip(userdomainlevels, targetdomainlevels)
    for user_element, target_element in zipped_tuples:
        if user_element != target_element:
            abort(403)
            
    if len(userdomainlevels) > len(targetdomainlevels):
        abort(403)

    if len(userdomainlevels) == len(targetdomainlevels) and loggeduser.user_manage_rights == ManagerTypesEnum.subdomain:
        abort(403)

    return True

def domain_filter(domain):
    return or_(User.domain.like(domain + domain_separator + '%'), User.domain == domain)