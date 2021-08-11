/*
 * Copyright 2010-2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

/**
 * @file subscribe_publish_sample.c
 * @brief simple MQTT publish and subscribe on the same topic
 *
 * This example takes the parameters from the aws_iot_config.h file and establishes a connection to the AWS IoT MQTT Platform.
 * It subscribes and publishes to the same topic - "sdkTest/sub"
 *
 * If all the certs are correct, you should see the messages received by the application in a loop.
 *
 * The application takes in the certificate path, host name , port and the number of times the publish should happen.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>

#include "aws_iot_config.h"
#include "aws_iot_json_utils.h"
#include "aws_iot_log.h"
#include "aws_iot_version.h"
#include "aws_iot_mqtt_client_interface.h"

#define HOST_ADDRESS_SIZE 255
#define CUSTOM_PATH_SIZE 255
#define MQTT_PAYLOAD_SIZE_MAX 1024
#define THNING_NAME_MAX 128
#define COMMAND_LINE_MAX 16
#define AWS_IOT_LOCAL_PROXY_BINARY "localproxy"
#define AWS_IOT_SECURE_TUNNEL_TOKEN "AWSIOT_TUNNEL_ACCESS_TOKEN"
#define AWS_IOT_SECURE_TUNNEL_REGION "AWSIOT_TUNNEL_REGION"

/**
 * @brief Default cert location
 */
static char certDirectory[PATH_MAX + 1] = "../../../certs";

/**
 * @brief Default MQTT HOST URL is pulled from the aws_iot_config.h
 */
static char HostAddress[HOST_ADDRESS_SIZE] = AWS_IOT_MQTT_HOST;

/**
 * @brief Custom AWS IoT Endpoint
 */
static char customAwsEndpoint[HOST_ADDRESS_SIZE];

/**
 * @brief Custom AWS Root CA path
 */
static char customRootCA[CUSTOM_PATH_SIZE];

/**
 * @brief Custom device certificate path
 */
static char customDeviceCertificate[CUSTOM_PATH_SIZE];

/**
 * @brief Custom device private key path
 */
static char customDevicePrivateKey[CUSTOM_PATH_SIZE];

/**
 * @brief Custom thing name
 */
static char customThingName[THNING_NAME_MAX + 1];

/**
 * @brief Default MQTT port is pulled from the aws_iot_config.h
 */
static uint32_t port = AWS_IOT_MQTT_PORT;

/**
 * @brief This parameter will avoid infinite loop of publish and exit the program after certain number of publishes
 */
static uint32_t publishCount = 0;

static void iot_subscribe_callback_handler(AWS_IoT_Client *pClient, char *topicName, uint16_t topicNameLen,
									IoT_Publish_Message_Params *params, void *pData) {
	IOT_UNUSED(pData);
	IOT_UNUSED(pClient);
	IOT_INFO("Subscribe callback");
	IOT_INFO("%.*s\t%.*s", topicNameLen, topicName, (int) params->payloadLen, (char *) params->payload);

	jsmn_parser jsonParser;
	jsmntok_t jsmntok_t *dataToken, jsonTokenStruct[MAX_JSON_TOKEN_EXPECTED];
	int32_t tokenCount, totalSize = 0;
	char cToken[MQTT_PAYLOAD_SIZE_MAX], cRegion[MQTT_PAYLOAD_SIZE_MAX];
	char *args[COMMAND_LINE_MAX] = {AWS_IOT_LOCAL_PROXY_BINARY, "-d", "1234", NULL};

	jsmn_init(&jsonParser);

	tokenCount = jsmn_parse(&jsonParser, params->payload, (int) params->payloadLen, jsonTokenStruct, MAX_JSON_TOKEN_EXPECTED);

	if(tokenCount < 0) {
		IOT_WARN("Failed to parse JSON: %d", tokenCount);
	}

	/* Assume the top-level element is an object */
	if(tokenCount < 1 || jsonTokenStruct[0].type != JSMN_OBJECT) {
		IOT_WARN("Top Level is not an object");
	}

	dataToken = findToken("clientAccessToken", params->payload, jsonTokenStruct);
	if (dataToken)
	{
		snprintf(cToken, MQTT_PAYLOAD_SIZE_MAX, "%.*s", dataToken->end - dataToken->start, (char *)params->payload + dataToken->start);
		totalSize += (dataToken->end - dataToken->start);

		dataToken = findToken("region", params->payload, jsonTokenStruct);
		if (dataToken)
		{
			snprintf(cRegion, MQTT_PAYLOAD_SIZE_MAX, "%.*s", dataToken->end - dataToken->start, (char *)params->payload + dataToken->start);
			totalSize += (dataToken->end - dataToken->start);

			/* Configure the environment variables for both AWS_IOT_SECURE_TUNNEL_TOKEN and AWS_IOT_SECURE_TUNNEL_REGION. */
			if (setenv(AWS_IOT_SECURE_TUNNEL_TOKEN, cToken, 1) == 0)
			{
				if (setenv(AWS_IOT_SECURE_TUNNEL_REGION, cRegion, 1) == 0)
				{
					/* Run localproxy with environment varialbes. */
					execv(AWS_IOT_LOCAL_PROXY_BINARY, args);
				}
				else
				{
					IOT_WARN("Configure AWS_IOT_SECURE_TUNNEL_REGION failed!");
				}
			}
			else
			{
				IOT_WARN("Configure AWS_IOT_SECURE_TUNNEL_TOKEN failed!");
			}
		}
		else
		{
			IOT_WARN("There is no region found in the payload");
		}
	}
	else
	{
		IOT_WARN("There is no token found in the payload");
	}
}

static void disconnectCallbackHandler(AWS_IoT_Client *pClient, void *data) {
	IOT_WARN("MQTT Disconnect");
	IoT_Error_t rc = FAILURE;

	if(NULL == pClient) {
		return;
	}

	IOT_UNUSED(data);

	if(aws_iot_is_autoreconnect_enabled(pClient)) {
		IOT_INFO("Auto Reconnect is enabled, Reconnecting attempt will start now");
	} else {
		IOT_WARN("Auto Reconnect not enabled. Starting manual reconnect...");
		rc = aws_iot_mqtt_attempt_reconnect(pClient);
		if(NETWORK_RECONNECTED == rc) {
			IOT_WARN("Manual Reconnect Successful");
		} else {
			IOT_WARN("Manual Reconnect Failed - %d", rc);
		}
	}
}

static void parseInputArgsForConnectParams(int argc, char **argv) {
	int opt;

	while(-1 != (opt = getopt(argc, argv, "h:p:c:x:r:k:t:"))) {
		switch(opt) {
			case 'h':
				strncpy(customAwsEndpoint, optarg, HOST_ADDRESS_SIZE);
				IOT_DEBUG("Host %s", optarg);
				break;
			case 'p':
				port = atoi(optarg);
				IOT_DEBUG("arg port %s", optarg);
				break;
			case 'c':
				strncpy(customDeviceCertificate, optarg, CUSTOM_PATH_SIZE);
				IOT_DEBUG("device certificate %s", optarg);
				break;
			case 'x':
				publishCount = atoi(optarg);
				IOT_DEBUG("publish %s times\n", optarg);
				break;
			case 'r':
				strncpy(customRootCA, optarg, CUSTOM_PATH_SIZE);
				IOT_DEBUG("AWS Root CA %s", optarg);
				break;
			case 'k':
				strncpy(customDevicePrivateKey, optarg, CUSTOM_PATH_SIZE);
				IOT_DEBUG("device private key %s", optarg);
				break;
			case 't':
				strncpy(customThingName, optarg, NAME_MAX);
				IOT_DEBUG("device thing name %s", optarg);
				break;
			case '?':
				if(optopt == 'c') {
					IOT_ERROR("Option -%c requires an argument.", optopt);
				} else if(isprint(optopt)) {
					IOT_WARN("Unknown option `-%c'.", optopt);
				} else {
					IOT_WARN("Unknown option character `\\x%x'.", optopt);
				}
				break;
			default:
				IOT_ERROR("Error in command line argument parsing");
				break;
		}
	}

}

int main(int argc, char **argv) {
	bool infinitePublishFlag = true;

	char rootCA[PATH_MAX + 1];
	char clientCRT[PATH_MAX + 1];
	char clientKey[PATH_MAX + 1];
	char CurrentWD[PATH_MAX + 1];
	char cPayload[100];
	/* The prefix of AWS IoT Secure Tunneling topic is $aws/things/, size is 12.
	 * And the postfix is /tunnels/notify, size is 15. */
	char cIoTSecureTunnelTopic[THNING_NAME_MAX + 27 + 1];

	int32_t i = 0;

	IoT_Error_t rc = FAILURE;

	AWS_IoT_Client client;
	IoT_Client_Init_Params mqttInitParams = iotClientInitParamsDefault;
	IoT_Client_Connect_Params connectParams = iotClientConnectParamsDefault;

	IoT_Publish_Message_Params paramsQOS0;
	IoT_Publish_Message_Params paramsQOS1;

	parseInputArgsForConnectParams(argc, argv);

	IOT_INFO("\nAWS IoT SDK Version %d.%d.%d-%s\n", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, VERSION_TAG);

	getcwd(CurrentWD, sizeof(CurrentWD));
	snprintf(rootCA, PATH_MAX + 1, "%s/%s/%s", CurrentWD, certDirectory, AWS_IOT_ROOT_CA_FILENAME);
	snprintf(clientCRT, PATH_MAX + 1, "%s/%s/%s", CurrentWD, certDirectory, AWS_IOT_CERTIFICATE_FILENAME);
	snprintf(clientKey, PATH_MAX + 1, "%s/%s/%s", CurrentWD, certDirectory, AWS_IOT_PRIVATE_KEY_FILENAME);

	IOT_DEBUG("rootCA %s", customRootCA);
	IOT_DEBUG("clientCRT %s", customDeviceCertificate);
	IOT_DEBUG("clientKey %s", customDevicePrivateKey);
	mqttInitParams.enableAutoReconnect = false; // We enable this later below
	mqttInitParams.pHostURL = customAwsEndpoint;
	mqttInitParams.port = port;
	mqttInitParams.pRootCALocation = customRootCA;
	mqttInitParams.pDeviceCertLocation = customDeviceCertificate;
	mqttInitParams.pDevicePrivateKeyLocation = customDevicePrivateKey;
	mqttInitParams.mqttCommandTimeout_ms = 20000;
	mqttInitParams.tlsHandshakeTimeout_ms = 5000;
	mqttInitParams.isSSLHostnameVerify = true;
	mqttInitParams.disconnectHandler = disconnectCallbackHandler;
	mqttInitParams.disconnectHandlerData = NULL;

	rc = aws_iot_mqtt_init(&client, &mqttInitParams);
	if(SUCCESS != rc) {
		IOT_ERROR("aws_iot_mqtt_init returned error : %d ", rc);
		return rc;
	}

	connectParams.keepAliveIntervalInSec = 600;
	connectParams.isCleanSession = true;
	connectParams.MQTTVersion = MQTT_3_1_1;
	connectParams.pClientID = AWS_IOT_MQTT_CLIENT_ID;
	connectParams.clientIDLen = (uint16_t) strlen(AWS_IOT_MQTT_CLIENT_ID);
	connectParams.isWillMsgPresent = false;

	IOT_INFO("Connecting...");
	rc = aws_iot_mqtt_connect(&client, &connectParams);
	if(SUCCESS != rc) {
		IOT_ERROR("Error(%d) connecting to %s:%d", rc, mqttInitParams.pHostURL, mqttInitParams.port);
		return rc;
	}
	/*
	 * Enable Auto Reconnect functionality. Minimum and Maximum time of Exponential backoff are set in aws_iot_config.h
	 *  #AWS_IOT_MQTT_MIN_RECONNECT_WAIT_INTERVAL
	 *  #AWS_IOT_MQTT_MAX_RECONNECT_WAIT_INTERVAL
	 */
	rc = aws_iot_mqtt_autoreconnect_set_status(&client, true);
	if(SUCCESS != rc) {
		IOT_ERROR("Unable to set Auto Reconnect to true - %d", rc);
		return rc;
	}

	IOT_INFO("Subscribing...");
	sprintf(cIoTSecureTunnelTopic, "%s%s%s", "$aws/things/", customThingName, "/tunnels/notify");
	rc = aws_iot_mqtt_subscribe(&client, cIoTSecureTunnelTopic, strlen(cIoTSecureTunnelTopic), QOS0, iot_subscribe_callback_handler, NULL);
	if(SUCCESS != rc) {
		IOT_ERROR("Error subscribing : %d ", rc);
		return rc;
	}

	sprintf(cPayload, "%s : %d ", "hello from SDK", i);

	paramsQOS0.qos = QOS0;
	paramsQOS0.payload = (void *) cPayload;
	paramsQOS0.isRetained = 0;

	paramsQOS1.qos = QOS1;
	paramsQOS1.payload = (void *) cPayload;
	paramsQOS1.isRetained = 0;

	if(publishCount != 0) {
		infinitePublishFlag = false;
	}

	while((NETWORK_ATTEMPTING_RECONNECT == rc || NETWORK_RECONNECTED == rc || SUCCESS == rc)
		  && (publishCount > 0 || infinitePublishFlag)) {

		//Max time the yield function will wait for read messages
		rc = aws_iot_mqtt_yield(&client, 100);
		if(NETWORK_ATTEMPTING_RECONNECT == rc) {
			// If the client is attempting to reconnect we will skip the rest of the loop.
			continue;
		}

		IOT_INFO("-->sleep");
		sleep(1);
		sprintf(cPayload, "%s : %d ", "hello from SDK QOS0", i++);
		paramsQOS0.payloadLen = strlen(cPayload);
		rc = aws_iot_mqtt_publish(&client, "sdkTest/sub", 11, &paramsQOS0);
		if(publishCount > 0) {
			publishCount--;
		}

		if(publishCount == 0 && !infinitePublishFlag) {
			break;
		}

		sprintf(cPayload, "%s : %d ", "hello from SDK QOS1", i++);
		paramsQOS1.payloadLen = strlen(cPayload);
		rc = aws_iot_mqtt_publish(&client, "sdkTest/sub", 11, &paramsQOS1);
		if (rc == MQTT_REQUEST_TIMEOUT_ERROR) {
			IOT_WARN("QOS1 publish ack not received.\n");
			rc = SUCCESS;
		}
		if(publishCount > 0) {
			publishCount--;
		}
	}

	// Wait for all the messages to be received
	aws_iot_mqtt_yield(&client, 100);

	if(SUCCESS != rc) {
		IOT_ERROR("An error occurred in the loop.\n");
	} else {
		IOT_INFO("Publish done\n");
	}

	return rc;
}
