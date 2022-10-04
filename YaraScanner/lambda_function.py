import json
import yara
import boto3

s3_client = boto3.client("s3")
def lambda_handler(event, context):
	print(event)
    
	bucket_name = "yarascan-s3"
	response = s3_client.list_objects_v2(Bucket=bucket_name)
	sample_list = [] 
	for samples in response['Contents']:
		if samples['Key'].startswith('samples'):
			sample_list.append(samples['Key'])
    
	print("samples: " , sample_list)
    
	uploaded_file = event['Records'][0]['s3']['object']['key']
    
	print('Uploaded file: ', uploaded_file)
    
	response = s3_client.get_object(Bucket=bucket_name, Key=uploaded_file)

	data = response['Body'].read().decode('utf-8')
	
	rules = yara.compile(source=data)
	match_status = []
	for i in sample_list:
		response = s3_client.get_object(Bucket=bucket_name, Key=i)
		data = response['Body'].read()
		matches = rules.match(data=data)
		#print(matches)
		if not matches:
			match_status.append(f"{i} did not match {uploaded_file}")
			
		else:
			match_status.append(f"{i} matched {uploaded_file}")
	print(match_status)
