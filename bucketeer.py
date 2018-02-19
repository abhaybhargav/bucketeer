import sublist3r
import dns.resolver
from termcolor import colored
import argparse
import yaml
import sys

bucketeer_desc = '''
Bucketeer is a small script that builds off the useful Sublist3r tool. 
The Tool tries to identify S3 Buckets and other useful subdomain information, 
that is used to perform subdomain takeover attacks.  
'''

bucketeer_logo = '''

.______    __    __    ______  __  ___  _______ .___________. _______  _______ .______      
|   _  \  |  |  |  |  /      ||  |/  / |   ____||           ||   ____||   ____||   _  \     
|  |_)  | |  |  |  | |  ,----'|  '  /  |  |__   `---|  |----`|  |__   |  |__   |  |_)  |    
|   _  <  |  |  |  | |  |     |    <   |   __|      |  |     |   __|  |   __|  |      /     
|  |_)  | |  `--'  | |  `----.|  .  \  |  |____     |  |     |  |____ |  |____ |  |\  \----.
|______/   \______/   \______||__|\__\ |_______|    |__|     |_______||_______|| _| `._____|
                                                                                            

'''

cname_lookups = ['cloudfront', 'amazonaws', 'zendesk', 'digitaloceanspaces']

sub_results = {}


def enum_sub_domains(domain, brute_force):
    if brute_force:
        sublist3r.main('{0}'.format(domain), 40, '{0}.txt'.format(domain), ports= None, silent=False, verbose=True, enable_bruteforce=brute_force, engines=',')
    else:
        sublist3r.main('{0}'.format(domain), 40, '{0}.txt'.format(domain), ports=None, silent=False, verbose=True,
                       enable_bruteforce=brute_force, engines=None)

def write_to_yaml(yaml_path):
    for x in list(sub_results.keys()):
        if sub_results[x] == []:
            del sub_results[x]

    with open(yaml_path, 'w') as outfile:
        yaml.dump(sub_results, outfile, default_flow_style = False)

def enum_cloud_subs(domain, yaml_path):
    try:
        with open('{0}.txt'.format(domain),'r') as subfile:
            for line in subfile.readlines():
                sub_results[line.rstrip()] = []
                try:
                    answers = dns.resolver.query(line.rstrip(), 'CNAME')
                except Exception as e:
                    pass
                for single in answers:
                    for cn in cname_lookups:
                        if cn in single.to_text():
                            sub_results[line.rstrip()].append(single.to_text())
    except KeyboardInterrupt:
        write_to_yaml(yaml_path)
        print("Bye...")





if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=bucketeer_desc)
    parser.add_argument("-d", action = "store", dest = "domain", help="Domain for which subdomains and cloud services is to be enumerated")
    parser.add_argument("--brute-only", action = "store_true", dest = "bruteforce_only", help="Bruteforce Subdomain and don not enumerate through Search Engines", default = False)
    # parser.add_argument("--ports", help = "Add ports like 80,443 to the process", default=None)
    parser.add_argument("-o", action = "store", dest = "output", help = "This will be a YAML file, which will have the `domain_name`.yaml by default")

    results = parser.parse_args()
    if not results.domain:
        sys.exit(1)
    else:
        if results.output == None:
            print(bucketeer_logo)
            enum_sub_domains(results.domain, brute_force=results.bruteforce_only)
            enum_cloud_subs(results.domain, "{0}.yml".format(results.domain))
            write_to_yaml("{0}.yml".format(results.domain))
        else:
            print(bucketeer_logo)
            enum_sub_domains(results.domain, brute_force=results.bruteforce_only)
            enum_cloud_subs(results.domain, results.output)
            write_to_yaml(results.output)









