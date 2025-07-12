#!/usr/bin/env python3
"""
Script to load all existing rule files from the rules/ directory into the database.
This will make all the built-in rules visible in the web interface.
"""

import os
import sys
import yaml
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, os.path.abspath('.'))

from api import create_app, db
from api.models.machine import Rule
from api.models.user import User, Role

def load_all_rules():
    """Load all rule files from the rules/ directory into the database"""
    
    # Create Flask app
    app = create_app()
    
    with app.app_context():
        # Ensure tables exist
        db.create_all()
        
        # Get admin user (create if doesn't exist)
        admin_user = User.query.filter_by(username="admin").first()
        if not admin_user:
            print("Creating admin user...")
            admin_role = Role.query.filter_by(name="admin").first()
            if not admin_role:
                admin_role = Role(name="admin", description="Administrator role")
                db.session.add(admin_role)
                db.session.commit()
            
            admin_user = User(username="admin", email="admin@example.com")
            admin_user.set_password("admin")
            admin_user.roles.append(admin_role)
            db.session.add(admin_user)
            db.session.commit()
        
        # Technology mapping for rule files
        tech_mapping = {
            'os_kernel.yml': ['os_kernel'],
            'memory_cpu.yml': ['memory_cpu'],
            'disk_filesystems.yml': ['disk_filesystems'],
            'processes_services.yml': ['processes_services'],
            'network.yml': ['network'],
            'routing.yml': ['routing'],
            'users_auth.yml': ['users_auth'],
            'history.yml': ['history'],
            'packages.yml': ['packages'],
            'docker.yml': ['docker'],
            'lxc.yml': ['lxc'],
            'selinux.yml': ['selinux'],
            'firewall.yml': ['firewall'],
            'kernel_params.yml': ['kernel_params'],
            'kernel_vuln.yml': ['kernel_vuln'],
            'shared_memory.yml': ['shared_memory'],
            'udev.yml': ['udev'],
            'dbus.yml': ['dbus'],
            'suid_sgid.yml': ['suid_sgid'],
            'world_writable.yml': ['world_writable'],
            'capabilities.yml': ['capabilities'],
            'env_umask.yml': ['env_umask'],
            'exports.yml': ['exports'],
            'rpc.yml': ['rpc'],
            'x_access.yml': ['x_access']
        }
        
        # Get descriptions for each technology
        tech_descriptions = {
            'os_kernel': 'Operating system and kernel information',
            'memory_cpu': 'Memory and CPU statistics',
            'disk_filesystems': 'Disk usage and filesystem details',
            'processes_services': 'Running processes and system services',
            'network': 'Network interfaces and connections',
            'routing': 'Network routing tables',
            'users_auth': 'User accounts and authentication configuration',
            'history': 'User login and shell history',
            'packages': 'Installed software packages',
            'docker': 'Docker container information',
            'lxc': 'LXC container information',
            'selinux': 'SELinux security status',
            'firewall': 'Firewall and packet filter rules',
            'kernel_params': 'Kernel parameters (sysctl)',
            'kernel_vuln': 'Kernel CPU vulnerability status',
            'shared_memory': 'Shared memory segments',
            'udev': 'udev rules and device events',
            'dbus': 'DBUS system information',
            'suid_sgid': 'SUID/SGID files',
            'world_writable': 'World-writable files',
            'capabilities': 'File capabilities',
            'env_umask': 'Environment variables and umask',
            'exports': 'NFS exports configuration',
            'rpc': 'RPC services and configuration',
            'x_access': 'X11 access control'
        }
        
        rules_dir = Path("rules")
        loaded_count = 0
        skipped_count = 0
        
        print("Loading existing rules from rules/ directory...")
        
        for rule_file in rules_dir.glob("*.yml"):
            filename = rule_file.name
            
            # Check if rule already exists in database
            existing_rule = Rule.query.filter_by(filename=filename).first()
            if existing_rule:
                print(f"Skipping {filename} - already exists in database")
                skipped_count += 1
                continue
            
            try:
                # Read the rule file
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule_data = f.read()
                
                # Get technologies for this rule file
                technologies = tech_mapping.get(filename, [])
                if not technologies:
                    print(f"Warning: No technology mapping for {filename}")
                    technologies = []
                
                # Create description from technologies
                tech_descriptions_list = [tech_descriptions.get(tech, tech) for tech in technologies]
                description = f"Built-in rules for: {', '.join(tech_descriptions_list)}"
                
                # Create the rule
                rule = Rule(
                    filename=filename,
                    data=rule_data.encode('utf-8'),
                    description=description,
                    user_id=admin_user.id,
                    technologies=technologies
                )
                
                db.session.add(rule)
                loaded_count += 1
                print(f"Loaded {filename} with technologies: {technologies}")
                
            except Exception as e:
                print(f"Error loading {filename}: {e}")
                continue
        
        # Commit all changes
        db.session.commit()
        
        print(f"\nLoading complete!")
        print(f"Loaded: {loaded_count} rules")
        print(f"Skipped: {skipped_count} rules (already exist)")
        print(f"Total rules in database: {Rule.query.count()}")

if __name__ == "__main__":
    load_all_rules() 