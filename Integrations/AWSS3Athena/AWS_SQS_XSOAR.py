import boto3
import json
import datetime

AWS_DEFAULT_REGION = demisto.params()['defaultRegion']
AWS_roleArn = demisto.params()['roleArn']
AWS_roleSessionName = demisto.params()['roleSessionName']
AWS_roleSessionDuration = demisto.params()['sessionDuration']
AWS_rolePolicy = None
AWS_QUEUEURL = demisto.params()['queueUrl']

def aws_session(service='sqs',region=None,roleArn=None,roleSessionName=None,roleSessionDuration=None,rolePolicy=None):
    kwargs = {}
    if roleArn and roleSessionName is not None:
        kwargs.update({
            'RoleArn':roleArn,
            'RoleSessionName':roleSessionName,
            })
    elif AWS_roleArn and AWS_roleSessionName is not None:
        kwargs.update({
            'RoleArn':AWS_roleArn,
            'RoleSessionName':AWS_roleSessionName,
            })

    if roleSessionDuration is not None:
        kwargs.update({'DurationSeconds':int(roleSessionDuration)})
    elif AWS_roleSessionDuration is not None:
        kwargs.update({'DurationSeconds':int(AWS_roleSessionDuration)})

    if rolePolicy is not None:
        kwargs.update({'Policy':rolePolicy})
    elif AWS_rolePolicy is not None:
        kwargs.update({'Policy':AWS_rolePolicy})

    if kwargs:
        sts_client = boto3.client('sts')
        sts_response = sts_client.assume_role(**kwargs)
        if region is not None:
            client = boto3.client(
                service_name=service,
                region_name=region,
                aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                aws_session_token=sts_response['Credentials']['SessionToken']
                )
        else:
            client = boto3.client(
                service_name=service,
                region_name=AWS_DEFAULT_REGION,
                aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                aws_session_token=sts_response['Credentials']['SessionToken']
                )
    else:
        if region is not None:
            client = boto3.client(service_name=service,region_name=region)
        else:
            client = boto3.client(service_name=service,region_name=AWS_DEFAULT_REGION)

    return client

def create_entry(title,data, ec):
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': data,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, data) if data else 'No result were found',
        'EntryContext': ec
    }

def raise_error(error):
    return {
        'Type' : entryTypes['error'],
        'ContentsFormat' : formats['text'],
        'Contents' : str(error)
    }

def get_queue_url(args):
    try:
        client = aws_session(
                region = args.get('region'),
                roleArn = args.get('roleArn'),
                roleSessionName = args.get('roleSessionName'),
                roleSessionDuration = args.get('roleSessionDuration'),
            )

        kwargs = {'QueueName':args.get('queueName')}
        if args.get('queueOwnerAWSAccountId'):
            kwargs.update({'QueueOwnerAWSAccountId':args.get('queueOwnerAWSAccountId')})

        response = client.get_queue_url(**kwargs)
        data = ({'QueueUrl':response['QueueUrl']})

        ec = {'AWS.SQS.Queues': data}
        return  create_entry('AWS SQS Queues',data, ec)

    except Exception as e:
        return raise_error(e)

def list_queues(args):
    try:
        client = aws_session(
                region = args.get('region'),
                roleArn = args.get('roleArn'),
                roleSessionName = args.get('roleSessionName'),
                roleSessionDuration = args.get('roleSessionDuration'),
            )

        data = []
        kwargs = {}
        if args.get('queueNamePrefix') is not None:
            kwargs.update({'QueueNamePrefix':args.get('queueNamePrefix')})
        response = client.list_queues(**kwargs)
        for queue in response['QueueUrls']:
            data.append({'QueueUrl':queue})

        ec = {'AWS.SQS.Queues': data}
        return  create_entry('AWS SQS Queues',data, ec)

    except Exception as e:
        return raise_error(e)

def send_message(args):
    try:
        client = aws_session(
                region = args.get('region'),
                roleArn = args.get('roleArn'),
                roleSessionName = args.get('roleSessionName'),
                roleSessionDuration = args.get('roleSessionDuration'),
            )

        kwargs = {
            'QueueUrl':args.get('queueUrl'),
            'MessageBody':args.get('messageBody'),
            }
        if args.get('delaySeconds') is not None:
            kwargs.update({'DelaySeconds':int(args.get('delaySeconds'))})
        if args.get('messageGroupId') is not None:
            kwargs.update({'MessageGroupId':int(args.get('messageGroupId'))})

        response = client.send_message(**kwargs)
        data = ({
            'QueueUrl': args.get('queueUrl'),
            'MessageId': response['MessageId'],
        })
        if 'SequenceNumber' in response: data.update({'SequenceNumber': response['SequenceNumber']})
        if 'MD5OfMessageBody' in response: data.update({'MD5OfMessageBody': response['MD5OfMessageBody']})
        if 'MD5OfMessageAttributes' in response: data.update({'MD5OfMessageAttributes': response['MD5OfMessageAttributes']})

        ec = {'AWS.SQS.Queues(obj.QueueUrl === val.QueueUrl).SentMessages': data}
        return  create_entry('AWS SQS Queues sent messages',data, ec)

    except Exception as e:
        return raise_error(e)

def create_queue(args):
    try:
        client = aws_session(
                region = args.get('region'),
                roleArn = args.get('roleArn'),
                roleSessionName = args.get('roleSessionName'),
                roleSessionDuration = args.get('roleSessionDuration'),
            )
        attributes = {}
        kwargs = {'QueueName':args.get('queueName')}
        if args.get('delaySeconds') is not None:
            attributes.update({'DelaySeconds':args.get('delaySeconds')})
        if args.get('maximumMessageSize') is not None:
            attributes.update({'MaximumMessageSize':args.get('maximumMessageSize')})
        if args.get('messageRetentionPeriod') is not None:
            attributes.update({'MessageRetentionPeriod':args.get('messageRetentionPeriod')})
        if args.get('receiveMessageWaitTimeSeconds') is not None:
            attributes.update({'ReceiveMessageWaitTimeSeconds':args.get('receiveMessageWaitTimeSeconds')})
        if args.get('visibilityTimeout') is not None:
            attributes.update({'VisibilityTimeout':int(args.get('visibilityTimeout'))})
        if args.get('kmsDataKeyReusePeriodSeconds') is not None:
            attributes.update({'KmsDataKeyReusePeriodSeconds':args.get('kmsDataKeyReusePeriodSeconds')})
        if args.get('kmsMasterKeyId') is not None:
            attributes.update({'KmsMasterKeyId':args.get('kmsMasterKeyId')})
        if args.get('policy') is not None:
            attributes.update({'Policy':args.get('policy')})
        if args.get('fifoQueue') is not None:
            attributes.update({'FifoQueue':args.get('fifoQueue')})
        if args.get('contentBasedDeduplication') is not None:
            attributes.update({'ContentBasedDeduplication':args.get('contentBasedDeduplication')})
        if attributes:
            kwargs.update({'Attributes':attributes})

        response = client.create_queue(**kwargs)
        data = ({'QueueUrl': response['QueueUrl']})
        ec = {'AWS.SQS.Queues': data}
        return  create_entry('AWS SQS Queues',data, ec)

    except Exception as e:
        return raise_error(e)

def delete_queue(args):
    try:
        client = aws_session(
                region = args.get('region'),
                roleArn = args.get('roleArn'),
                roleSessionName = args.get('roleSessionName'),
                roleSessionDuration = args.get('roleSessionDuration'),
            )
        response = client.delete_queue(QueueUrl=args.get('queueUrl'))
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return 'The Queue has been deleted'

    except Exception as e:
        return raise_error(e)

def purge_queue(args):
    try:
        client = aws_session(
                region = args.get('region'),
                roleArn = args.get('roleArn'),
                roleSessionName = args.get('roleSessionName'),
                roleSessionDuration = args.get('roleSessionDuration'),
            )
        response = client.purge_queue(QueueUrl=args.get('queueUrl'))
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return 'The Queue has been Purged'

    except Exception as e:
        return raise_error(e)


def parse_incident_from_finding(message):
    incident = {}
    incident['name'] = "SQS MessageId: " + message["MessageId"]
    incident['rawJSON'] = json.dumps(message)
    return incident

def fetch_incidents():
    try:
        client = aws_session()
        messages = client.receive_message(
            QueueUrl=AWS_QUEUEURL,
            MaxNumberOfMessages=10,
            VisibilityTimeout=5,
            WaitTimeSeconds=5,
        )

        receipt_handles = []
        incidents = []

        if "Messages" not in messages.keys():
            if demisto.command() == 'fetch-incidents':
                demisto.incidents([])
            return messages,incidents,receipt_handles

        for message in messages["Messages"]:
            receipt_handles.append(message['ReceiptHandle'])
            incidents.append(parse_incident_from_finding(message))

        demisto.incidents(incidents)
        if receipt_handles is not None:
            #Archive findings
            for receipt_handle in receipt_handles:
                client.delete_message(QueueUrl=AWS_QUEUEURL, ReceiptHandle=receipt_handle)


    except Exception as e:
        return raise_error(e)

def test_function():
    try:
        client = aws_session()
        response = client.list_queues()
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return "ok"
    except Exception as e:
        return raise_error(e)

# The command demisto.command() holds the command sent from the user.
if demisto.command() == 'test-module':
    # This is the call made when pressing the integration test button.
    result = test_function()

if demisto.command() == 'aws-sqs-get-queue-url':
    result = get_queue_url(demisto.args())

if demisto.command() == 'aws-sqs-list-queues':
    result = list_queues(demisto.args())

if demisto.command() == 'aws-sqs-send-message':
    result = send_message(demisto.args())

if demisto.command() == 'aws-sqs-create-queue':
    result = create_queue(demisto.args())

if demisto.command() == 'aws-sqs-delete-queue':
    result = delete_queue(demisto.args())

if demisto.command() == 'aws-sqs-purge-queue':
    result = purge_queue(demisto.args())

if demisto.command() == 'fetch-incidents':
    fetch_incidents()
    sys.exit(0)

demisto.results(result)
sys.exit(0)

