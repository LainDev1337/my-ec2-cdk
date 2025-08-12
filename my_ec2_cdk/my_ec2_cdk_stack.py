import aws_cdk as cdk
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_iam as iam
from constructs import Construct

class MyEc2CdkStack(cdk.Stack):
    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        vpc = ec2.Vpc(self, "MyVpc",
            max_azs=2,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="Public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24
                )
            ]
        )

        security_group = ec2.SecurityGroup(self, "MySecurityGroup",
            vpc=vpc,
            allow_all_outbound=True
        )
        for port, desc in [(3389, "RDP"), (22, "SSH"), (80, "HTTP"), (443, "HTTPS")]:
            security_group.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(port), f"Allow {desc}")
        security_group.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.icmp_ping(), "Allow ICMP ping")

        role = iam.Role(self, "Ec2Role",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com")
        )
        role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"))
        role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AWSCodeDeployFullAccess"))
        role.add_to_policy(iam.PolicyStatement(
            actions=["s3:GetObject", "s3:ListBucket"],
            resources=[
                "arn:aws:s3:::sergeicvbucket",
                "arn:aws:s3:::sergeicvbucket/*"
            ]
        ))

        user_data = ec2.UserData.for_windows()
        user_data.add_commands(
            "netsh advfirewall set allprofiles state off",
            "Enable-PSRemoting -Force",
            r"Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 0",
            "Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'",
            "Restart-Service TermService",
            "Install-WindowsFeature -Name Web-Server -IncludeManagementTools",
            "Install-WindowsFeature -Name NET-Framework-45-Core",
             "Start-Sleep -Seconds 10",
            "if (!(Test-Path 'C:\\inetpub\\wwwroot\\sergei')) {",
            "    echo Creating folder sergei >> C:\\setup.log",
            "    New-Item -Path 'C:\\inetpub\\wwwroot\\sergei' -ItemType Directory -Force",
            "}",
            "$ErrorActionPreference = 'Stop';",
            "Invoke-WebRequest -Uri 'https://awscli.amazonaws.com/AWSCLIV2.msi' -OutFile 'C:\\AWSCLIV2.msi' -UseBasicParsing",
            "Start-Process -FilePath 'C:\\AWSCLIV2.msi' -ArgumentList '/quiet /norestart' -Wait",
            "[System.Environment]::SetEnvironmentVariable('Path', $env:Path + ';C:\\Program Files\\Amazon\\AWSCLIV2;C:\\Windows\\System32\\inetsrv', [System.EnvironmentVariableTarget]::Machine)",
            "Start-Sleep -Seconds 20",
            "aws s3 cp s3://sergeicvbucket C:\\inetpub\\wwwroot\\sergei\\ --recursive --region us-east-1",
            "Start-Sleep -Seconds 20"
            "Import-Module WebAdministration"
            r"Set-ItemProperty 'IIS:\Sites\Default Web Site' -Name physicalPath -Value 'C:\inetpub\wwwroot\sergei' >> C:\\iis.log 2>&1"
            "iisreset"
        )

        key_pair = ec2.KeyPair.from_key_pair_name(self, "MyKeyPair", key_pair_name="my-key-pair")

        ec2_instance = ec2.Instance(self, "MyWindowsInstance",
           instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
        machine_image=ec2.MachineImage.latest_windows(ec2.WindowsVersion.WINDOWS_SERVER_2019_ENGLISH_FULL_BASE),
        vpc=vpc,
        vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
        security_group=security_group,
        key_pair=key_pair,
        role=role,
        user_data=user_data
        )
        cdk.Tags.of(ec2_instance).add("Name", "MyWindowsInstance")

        eip = ec2.CfnEIP(self, "MyElasticIP")
        ec2.CfnEIPAssociation(self, "EIPAssociation",
            instance_id=ec2_instance.instance_id,
            allocation_id=eip.attr_allocation_id
        )

        cdk.CfnOutput(self, "InstancePublicIP", value=eip.attr_public_ip)
        cdk.CfnOutput(self, "InstanceId", value=ec2_instance.instance_id)
        cdk.CfnOutput(self, "TestWebsiteUrl", value=f"http://{eip.attr_public_ip}")

app = cdk.App()
MyEc2CdkStack(app, "MyEc2CdkStack")
app.synth()
