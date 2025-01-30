#!/usr/bin/env python
# coding: utf-8

# ## Cloud Misconfiguration Scanner

# ### Install Dependencies

# In[8]:


get_ipython().system('pip install boto3 flask pandas python-dotenv')


# ### AWS Scanner (aws_scanner.py)

# In[2]:


import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

class AWSScanner:
    def __init__(self):
        self.ec2_client = boto3.client('ec2')
        self.s3_client = boto3.client('s3')
        self.iam_client = boto3.client('iam')
        self.rds_client = boto3.client('rds')

    def scan_ec2_instances(self):
        try:
            instances = self.ec2_client.describe_instances()
            misconfigurations = []
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    if 'PublicIpAddress' in instance:
                        misconfigurations.append({
                            'ResourceId': instance['InstanceId'],
                            'Issue': 'Public IP assigned',
                            'Severity': 'High'
                        })
            return misconfigurations
        except (NoCredentialsError, PartialCredentialsError):
            return {"error": "AWS credentials not found or invalid"}


# In[3]:


scanner = AWSScanner()
ec2_misconfigs = scanner.scan_ec2_instances()

all_misconfigs = ec2_misconfigs

assessment = ConfigAssessment(all_misconfigs)
compliance_status = assessment.evaluate_compliance()
print("Compliance Status:", compliance_status)

risk_scoring = RiskScoring(all_misconfigs)
risk_score = risk_scoring.calculate_risk_score()
print("Risk Score:", risk_score)

reporting = Reporting(all_misconfigs)
reporting.generate_csv('report.csv')
reporting.generate_json('report.json')


# ### Configuration Assessment Engine

# In[4]:


class ConfigAssessment:
    def __init__(self, misconfigurations):
        self.misconfigurations = misconfigurations

    def evaluate_compliance(self):
        compliance_status = {
            'CIS': True,
            'NIST': True,
            'PCI': True
        }
        for misconfig in self.misconfigurations:
            if misconfig['Severity'] == 'Critical':
                compliance_status['CIS'] = False
                compliance_status['NIST'] = False
                compliance_status['PCI'] = False
        return compliance_status


# ### Risk Scoring Algorithm (risk_scoring.py)

# In[5]:


class RiskScoring:
    def __init__(self, misconfigurations):
        self.misconfigurations = misconfigurations

    def calculate_risk_score(self):
        risk_score = 0
        severity_weights = {
            'Critical': 10,
            'High': 7,
            'Medium': 4,
            'Low': 1
        }
        for misconfig in self.misconfigurations:
            risk_score += severity_weights.get(misconfig['Severity'], 0)
        return risk_score


# ### Reporting System (reporting.py)

# In[6]:


import pandas as pd
import json

class Reporting:
    def __init__(self, misconfigurations):
        self.misconfigurations = misconfigurations

    def generate_csv(self, filename):
        df = pd.DataFrame(self.misconfigurations)
        df.to_csv(filename, index=False)

    def generate_json(self, filename):
        with open(filename, 'w') as f:
            json.dump(self.misconfigurations, f)


# ### Run the Scanner

# In[7]:


scanner = AWSScanner()
ec2_misconfigs = scanner.scan_ec2_instances()

all_misconfigs = ec2_misconfigs

assessment = ConfigAssessment(all_misconfigs)
compliance_status = assessment.evaluate_compliance()
print("Compliance Status:", compliance_status)

risk_scoring = RiskScoring(all_misconfigs)
risk_score = risk_scoring.calculate_risk_score()
print("Risk Score:", risk_score)

reporting = Reporting(all_misconfigs)
reporting.generate_csv('report.csv')
reporting.generate_json('report.json')


# In[ ]:




