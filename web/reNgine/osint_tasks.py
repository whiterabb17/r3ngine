import logging
import os
import json
import csv
import subprocess
import shutil
import re
import threading
from reNgine.common_func import (
    get_random_proxy,
)
from reNgine.utils.task import save_email, save_employee
from reNgine.utils.opsec import OpSecManager, ProxychainsWrapper
from startScan.models import ScanHistory, Email, Employee
from scanEngine.models import Proxy
from reNgine.definitions import *
from reNgine.osint.linkedin_intelligence import LinkedInScraper
from dashboard.models import LinkedInCredentials, HunterIOAPIKey
from reNgine.osint.hunter_lookup import run_hunter_lookup

logger = logging.getLogger(__name__)

def run_holehe(email_address, scan_history_id):
    """
    Run holehe for a specific email address to find associated social media accounts.
    """
    try:
        scan_history = ScanHistory.objects.get(pk=scan_history_id)
        proxy_obj = Proxy.objects.first()
        proxy = get_random_proxy() if proxy_obj and proxy_obj.use_proxy else None
        
        cmd = ['holehe', email_address, '--only-used']
        
        # holehe doesn't have a direct JSON output to file via CLI easily in some versions, 
        # but we can capture stdout or check if we can use it as a library.
        # For now, let's run it and capture the output.
        
        if proxy:
            # Wrap with proxychains if needed or use holehe's proxy support if available
            # holehe doesn't have native proxy flags in all versions
            cmd = ['proxychains4', '-q'] + cmd
            
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        
        # Simple parsing of holehe output
        found_sites = []
        for line in stdout.splitlines():
            if '[+]' in line:
                site = line.split('[+]')[1].strip()
                found_sites.append(site)
        
        if found_sites:
            email, _ = save_email(email_address, scan_history=scan_history)
            metadata = email.metadata or {}
            metadata['holehe'] = found_sites
            email.metadata = metadata
            email.save()
            
        return found_sites
    except Exception as e:
        logger.error(f"Error running holehe for {email_address}: {str(e)}")
        return []

def run_maigret(username, scan_history_id):
    """
    Run maigret to find social media profiles for a given username.
    """
    try:
        scan_history = ScanHistory.objects.get(pk=scan_history_id)
        results_dir = f"{scan_history.results_dir}/osint/maigret"
        os.makedirs(results_dir, exist_ok=True)
        
        output_file = f"{results_dir}/{username}.json"
        
        proxy_obj = Proxy.objects.first()
        proxy = get_random_proxy() if proxy_obj and proxy_obj.use_proxy else None
        
        cmd = ['maigret', username, '--json', output_file]
        
        if proxy:
            # maigret supports --proxy
            cmd += ['--proxy', proxy]
            
        subprocess.run(cmd, capture_output=True, text=True)
        
        profiles = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                data = json.load(f)
                # maigret JSON structure varies, but we want the list of sites found
                for site, info in data.get('results', {}).items():
                    if info.get('status') == 'CLAIMED':
                        profiles.append({
                            'site': site,
                            'url': info.get('url_user')
                        })
        
        if profiles:
            employee, _ = save_employee(username, scan_history=scan_history)
            metadata = employee.metadata or {}
            metadata['maigret'] = profiles
            employee.metadata = metadata
            employee.save()
            
        return profiles
    except Exception as e:
        logger.error(f"Error running maigret for {username}: {str(e)}")
        return []

def run_linkedint(company_name, scan_history_id):
    """
    Run LinkedIn Scraper (Playwright) to scrape employees for a company.
    Returns a list of result strings. Never raises — logs notes on auth failure.
    """
    try:
        scan_history = ScanHistory.objects.get(pk=scan_history_id)
        domain = scan_history.domain.name

        session = LinkedInCredentials.objects.first()
        hunter_key = HunterIOAPIKey.objects.first()

        if not session:
            logger.warning("LinkedIn session not configured for %s. Skipping.", company_name)
            return []

        if not hunter_key or not hunter_key.key:
            logger.warning("Hunter.io API key not configured for %s. Skipping.", company_name)
            return []

        with LinkedInScraper(session=session, hunter_key=hunter_key.key) as scraper:
            employees = scraper.discover_employees(company_name, domain, scan_history)

            for note in scraper.notes:
                logger.warning("%s", note)

            if employees:
                for emp_data in employees:
                    emp, _ = save_employee(emp_data['name'], scan_history=scan_history)
                    emp.designation = emp_data['designation']
                    emp.save()
                    if 'email' in emp_data:
                        save_email(emp_data['email'], scan_history=scan_history)

            return [f"LinkedIn Intelligence processed {len(employees)} employees for {company_name}"]

    except Exception as exc:
        logger.error("Error running LinkedIn Intelligence for %s: %s", company_name, type(exc).__name__)
        return []



def enrich_identities_task(identity, identity_type, scan_history_id, ctx={}):
    """
    Enrich identities using username-anarchy and gosearch.
    identity: Email or Name
    identity_type: 'email' or 'employee'
    """
    from startScan.models import OsintStaging, Domain
    scan_history = ScanHistory.objects.get(pk=scan_history_id)
    domain = scan_history.domain
    
    results_dir = f"{scan_history.results_dir}/osint/gosearch"
    os.makedirs(results_dir, exist_ok=True)
    
    full_name = identity
    if identity_type == 'email':
        # Logic: mark.person@email.com -> Mark Person
        user_part = identity.split('@')[0]
        if '.' in user_part:
            full_name = ' '.join([p.capitalize() for p in user_part.split('.')])
        else:
            # If no dot, just use the username part
            full_name = user_part
            
    logger.info(f"Enriching identity: {full_name} ({identity_type})")
    
    # 1. Generate Top 5 usernames using username-anarchy
    # Command: username-anarchy "First Last"
    # We'll take the top 5 results
    ua_cmd = 'username-anarchy'
    if not shutil.which(ua_cmd):
        ua_cmd = '/usr/src/github/username-anarchy/username-anarchy'
        if not os.path.exists(ua_cmd):
            logger.error(f"username-anarchy not found")
            return
        
    cmd_ua = [ua_cmd, full_name]
    process_ua = subprocess.Popen(cmd_ua, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout_ua, _ = process_ua.communicate()
    
    usernames = [line.strip() for line in stdout_ua.splitlines() if line.strip()][:5]
    
    if not usernames and identity_type == 'email':
        # Fallback to the actual username from email
        usernames = [identity.split('@')[0]]
 
    logger.info(f"Generated usernames for {full_name}: {usernames}")
    
    # 2. Run gosearch for each username
    for username in usernames:
        if not username: continue
        
        # gosearch -u <username> --no-false-positives
        # We'll run it and parse output. gosearch output can be noisy.
        # It usually outputs discovered URLs.
        
        cmd_gs = ['gosearch', '-u', username, '--no-false-positives', '-o', results_dir]
        
        # Check for proxy in ctx or global
        proxy_obj = Proxy.objects.first()
        proxy = get_random_proxy() if proxy_obj and proxy_obj.use_proxy else None
        if proxy:
            cmd_gs = ['proxychains4', '-q'] + cmd_gs
            
        process_gs = subprocess.Popen(cmd_gs, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout_gs, _ = process_gs.communicate()
        
        findings = []
        for line in stdout_gs.splitlines():
            if 'http' in line:
                # Extract URL
                urls = re.findall(r'(https?://[^\s]+)', line)
                findings.extend(urls)
        
        if findings:
            for url in set(findings):
                OsintStaging.objects.get_or_create(
                    scan_history=scan_history,
                    target_domain=domain,
                    osint_type='Social/Web Presence',
                    content=url,
                    defaults={
                        'source': 'gosearch',
                        'confidence': 80,
                        'metadata': {
                            'username': username,
                            'identity': full_name,
                            'original_identity': identity
                        }
                    }
                )
    
    return f"Enrichment completed for {full_name}"

def db_conn_safe_wrapper(target_func, *args, **kwargs):
    from django.db import connections
    try:
        return target_func(*args, **kwargs)
    finally:
        connections.close_all()


def osint_orchestrator(scan_history_id):
    """
    Orchestrate the OSINT pipeline.
    """
    scan_history = ScanHistory.objects.get(pk=scan_history_id)
    domain = scan_history.domain.name

    # Run Hunter.io lookup synchronously first so discovered emails and
    # employees are in the DB before holehe/maigret/LinkedIn threads spawn.
    hunter_key_obj = HunterIOAPIKey.objects.first()
    if hunter_key_obj and hunter_key_obj.key:
        run_hunter_lookup(domain, scan_history_id, hunter_key_obj.key)

    threads = []
    
    # 1. Get already discovered emails
    emails = scan_history.emails.all()
    for email in emails:
        t1 = threading.Thread(
            target=db_conn_safe_wrapper,
            args=(run_holehe,),
            kwargs={'email_address': email.address, 'scan_history_id': scan_history_id},
            daemon=True
        )
        t1.start()
        threads.append(t1)
        
        t2 = threading.Thread(
            target=db_conn_safe_wrapper,
            args=(enrich_identities_task,),
            kwargs={'identity': email.address, 'identity_type': 'email', 'scan_history_id': scan_history_id},
            daemon=True
        )
        t2.start()
        threads.append(t2)

    # 2. Get already discovered employees/usernames
    employees = scan_history.employees.all()
    for employee in employees:
        if employee.name:
            if ' ' not in employee.name:
                t3 = threading.Thread(
                    target=db_conn_safe_wrapper,
                    args=(run_maigret,),
                    kwargs={'username': employee.name, 'scan_history_id': scan_history_id},
                    daemon=True
                )
                t3.start()
                threads.append(t3)
            
            t4 = threading.Thread(
                target=db_conn_safe_wrapper,
                args=(enrich_identities_task,),
                kwargs={'identity': employee.name, 'identity_type': 'employee', 'scan_history_id': scan_history_id},
                daemon=True
            )
            t4.start()
            threads.append(t4)

    # 3. LinkedInt for the domain/company
    company_name = domain.split('.')[0]
    t5 = threading.Thread(
        target=db_conn_safe_wrapper,
        args=(run_linkedint,),
        kwargs={'company_name': company_name, 'scan_history_id': scan_history_id},
        daemon=True
    )
    t5.start()
    threads.append(t5)

    # Wait for all threads to complete to ensure the Temporal activity blocks appropriately
    for t in threads:
        t.join()

