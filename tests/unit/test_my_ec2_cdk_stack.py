import aws_cdk as core
import aws_cdk.assertions as assertions

from my_ec2_cdk.my_ec2_cdk_stack import MyEc2CdkStack

# example tests. To run these tests, uncomment this file along with the example
# resource in my_ec2_cdk/my_ec2_cdk_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = MyEc2CdkStack(app, "my-ec2-cdk")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
