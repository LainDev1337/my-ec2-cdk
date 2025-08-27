import aws_cdk as cdk
from constructs import Construct

from aws_cdk import (
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_route53 as route53,
    aws_route53_targets as r53_targets,
    aws_elasticloadbalancingv2 as elbv2,
    aws_elasticloadbalancingv2_targets as elbv2_targets,
    aws_certificatemanager as acm,
)


class MyEc2CdkStack(cdk.Stack):
    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # VPC
        vpc = ec2.Vpc(self, "MyVpc", max_azs=2)

        # Security groups
        alb_sg = ec2.SecurityGroup(self, "AlbSG", vpc=vpc, allow_all_outbound=True)
        alb_sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(80))
        alb_sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(443))

        instance_sg = ec2.SecurityGroup(self, "InstanceSG", vpc=vpc, allow_all_outbound=True)
        # allow traffic from ALB to instance (HTTP)
        instance_sg.add_ingress_rule(alb_sg, ec2.Port.tcp(80))
        # allow RDP for admin
        instance_sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(3389))

        # IAM role
        role = iam.Role(self, "Ec2Role", assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"))
        role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"))
        role.add_to_policy(iam.PolicyStatement(
            actions=["s3:GetObject", "s3:ListBucket"],
            resources=["arn:aws:s3:::sergeicvbucket", "arn:aws:s3:::sergeicvbucket/*"],
        ))

        # User data: install IIS, Git, AWS CLI and clone the repo into wwwroot
        user_data = ec2.UserData.for_windows()
        user_data.add_commands(
            "powershell -Command \"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force\"",
            "netsh advfirewall set allprofiles state off",
            "Enable-PSRemoting -Force",
            r"Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 0",
            "Install-WindowsFeature -Name Web-Server -IncludeManagementTools",
            "Install-WindowsFeature -Name NET-Framework-45-Core",
            "Start-Sleep -Seconds 10",

            "# Install Git (silent) with User-Agent to avoid blocking",
            "Invoke-WebRequest -Uri 'https://github.com/git-for-windows/git/releases/download/v2.45.1.windows.1/Git-2.45.1-64-bit.exe' -OutFile 'C:\\Git-Setup.exe' -Headers @{ 'User-Agent' = 'Mozilla/5.0 (Windows NT)' }",
            "Start-Process -FilePath 'C:\\Git-Setup.exe' -ArgumentList '/VERYSILENT','/NORESTART' -Wait -NoNewWindow",
            "setx PATH ($env:PATH + ';C:\\Program Files\\Git\\cmd') /M",
            "Start-Sleep -Seconds 5",

            "# Install AWS CLI",
            "Invoke-WebRequest -Uri 'https://awscli.amazonaws.com/AWSCLIV2.msi' -OutFile 'C:\\AWSCLIV2.msi' -Headers @{ 'User-Agent' = 'Mozilla/5.0 (Windows NT)' }",
            "Start-Process -FilePath 'C:\\Windows\\System32\\msiexec.exe' -ArgumentList '/i','C:\\AWSCLIV2.msi','/qn','/norestart' -Wait -NoNewWindow",
            "setx PATH ($env:PATH + ';C:\\Program Files\\Amazon\\AWSCLIV2') /M",
            "Start-Sleep -Seconds 5",

            "# Clone website directly into wwwroot (no sergei folder)",
            "cd C:\\inetpub\\wwwroot",
            "if (!(Test-Path '.git')) { if (Test-Path 'C:\\Program Files\\Git\\cmd\\git.exe') { & 'C:\\Program Files\\Git\\cmd\\git.exe' clone https://github.com/LainDev1337/MyWebsiteRepo.git . } else { Write-Output 'git not found' >> C:\\setup.log } }",
            "Import-Module WebAdministration",
            r"Set-ItemProperty 'IIS:\\Sites\\Default Web Site' -Name physicalPath -Value 'C:\\inetpub\\wwwroot'",
            "iisreset"
        )

        # EC2 Instance
        ec2_instance = ec2.Instance(
            self, "MyWindowsInstance",
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
            machine_image=ec2.MachineImage.latest_windows(ec2.WindowsVersion.WINDOWS_SERVER_2019_ENGLISH_FULL_BASE),
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            security_group=instance_sg,
            key_name="my-key-pair",
            role=role,
            user_data=user_data,
        )
        cdk.Tags.of(ec2_instance).add("Name", "MyWindowsInstance")

        # Route53 hosted zone lookup
        hosted_zone = route53.HostedZone.from_lookup(self, "SergeiZone", domain_name="sergeikorwin.com")

        # ACM certificate validated by DNS
        cert = acm.Certificate(self, "SiteCert",
            domain_name="sergeikorwin.com",
            subject_alternative_names=["www.sergeikorwin.com"],
            validation=acm.CertificateValidation.from_dns(hosted_zone)
        )

        # ALB
        alb = elbv2.ApplicationLoadBalancer(self, "PublicALB", vpc=vpc, internet_facing=True, security_group=alb_sg)

        alb.add_listener("HttpListener", port=80, open=True, default_action=elbv2.ListenerAction.redirect(protocol="HTTPS", port="443", permanent=True))

        https_listener = alb.add_listener("HttpsListener", port=443, certificates=[elbv2.ListenerCertificate(cert.certificate_arn)], open=True)

        https_listener.add_targets("EC2Target", port=80, targets=[elbv2_targets.InstanceTarget(ec2_instance, port=80)], health_check=elbv2.HealthCheck(path='/', healthy_http_codes='200-399'))

        # DNS records pointing to ALB
        route53.ARecord(self, "RootAlias", zone=hosted_zone, target=route53.RecordTarget.from_alias(r53_targets.LoadBalancerTarget(alb)))
        route53.ARecord(self, "WWWAlias", zone=hosted_zone, record_name="www", target=route53.RecordTarget.from_alias(r53_targets.LoadBalancerTarget(alb)))

        # Outputs
        cdk.CfnOutput(self, "ALBDNS", value=alb.load_balancer_dns_name)
        cdk.CfnOutput(self, "DomainURL", value="https://sergeikorwin.com")
        cdk.CfnOutput(self, "InstanceId", value=ec2_instance.instance_id)



