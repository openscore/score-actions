/*
 * (c) Copyright 2018 Micro Focus, L.P.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0 which accompany this distribution.
 *
 * The Apache License is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.cloudslang.content.amazon.actions.servicecatalog;

import com.amazonaws.services.cloudformation.AmazonCloudFormation;
import com.amazonaws.services.cloudformation.model.Stack;
import com.amazonaws.services.servicecatalog.AWSServiceCatalog;
import com.amazonaws.services.servicecatalog.model.ProvisionProductResult;
import com.hp.oo.sdk.content.annotations.Action;
import com.hp.oo.sdk.content.annotations.Output;
import com.hp.oo.sdk.content.annotations.Param;
import com.hp.oo.sdk.content.annotations.Response;
import com.hp.oo.sdk.content.plugin.ActionMetadata.MatchType;
import com.hp.oo.sdk.content.plugin.ActionMetadata.ResponseType;
import io.cloudslang.content.amazon.entities.constants.Outputs;
import io.cloudslang.content.amazon.entities.validators.Validator;
import io.cloudslang.content.amazon.factory.CloudFormationClientBuilder;
import io.cloudslang.content.amazon.factory.ServiceCatalogClientBuilder;
import io.cloudslang.content.amazon.services.AmazonServiceCatalogService;
import io.cloudslang.content.amazon.utils.DefaultValues;

import java.util.List;
import java.util.Map;

import static io.cloudslang.content.amazon.entities.constants.Constants.ServiceCatalogActions.CREATE_COMPLETE;
import static io.cloudslang.content.amazon.entities.constants.Constants.ServiceCatalogActions.CREATE_IN_PROGRESS;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.Common.ASYNC_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.Common.CONNECT_TIMEOUT_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.Common.CREDENTIAL_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.Common.EXCEPTION_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.Common.EXECUTION_TIMEOUT_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.Common.IDENTITY_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.Common.PROXY_HOST_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.Common.PROXY_PASSWORD_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.Common.PROXY_PORT_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.Common.PROXY_USERNAME_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.Common.RETURN_CODE_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.Common.RETURN_RESULT_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.ACCEPT_LANGUAGE_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.CREATED_TIME_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.DELIMITER_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.FAILURE_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.NOTIFICATION_ARNS_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.PATH_ID_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.POLLING_INTERVAL_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.PRODUCT_ID_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.PROVISIONED_PRODUCT_ID_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.PROVISIONED_PRODUCT_NAME_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.PROVISIONED_PRODUCT_TYPE_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.PROVISIONING_ARTIFACT_ID_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.PROVISIONING_ARTIFACT_ID_OUT_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.PROVISIONING_PARAMETERS_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.PROVISION_PRODUCT_DESCRIPTION;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.PROVISION_TOKEN_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.REGION_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.STACK_ID_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.STACK_NAME_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.STACK_OUTPUTS_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.STACK_RESOURCES_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.STATUS_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.SUCCESS_DESC;
import static io.cloudslang.content.amazon.entities.constants.Descriptions.ProvisionProductAction.TAGS_DESC;
import static io.cloudslang.content.amazon.entities.constants.Inputs.CommonInputs.ASYNC;
import static io.cloudslang.content.amazon.entities.constants.Inputs.CommonInputs.CONNECT_TIMEOUT;
import static io.cloudslang.content.amazon.entities.constants.Inputs.CommonInputs.CREDENTIAL;
import static io.cloudslang.content.amazon.entities.constants.Inputs.CommonInputs.DELIMITER;
import static io.cloudslang.content.amazon.entities.constants.Inputs.CommonInputs.EXECUTION_TIMEOUT;
import static io.cloudslang.content.amazon.entities.constants.Inputs.CommonInputs.IDENTITY;
import static io.cloudslang.content.amazon.entities.constants.Inputs.CommonInputs.POLLING_INTERVAL;
import static io.cloudslang.content.amazon.entities.constants.Inputs.CommonInputs.PROXY_HOST;
import static io.cloudslang.content.amazon.entities.constants.Inputs.CommonInputs.PROXY_PASSWORD;
import static io.cloudslang.content.amazon.entities.constants.Inputs.CommonInputs.PROXY_PORT;
import static io.cloudslang.content.amazon.entities.constants.Inputs.CommonInputs.PROXY_USERNAME;
import static io.cloudslang.content.amazon.entities.constants.Inputs.CommonInputs.REGION;
import static io.cloudslang.content.amazon.entities.constants.Inputs.ServiceCatalogInputs.ACCEPT_LANGUAGE;
import static io.cloudslang.content.amazon.entities.constants.Inputs.ServiceCatalogInputs.NOTIFICATION_ARNS;
import static io.cloudslang.content.amazon.entities.constants.Inputs.ServiceCatalogInputs.PATH_ID;
import static io.cloudslang.content.amazon.entities.constants.Inputs.ServiceCatalogInputs.PRODUCT_ID;
import static io.cloudslang.content.amazon.entities.constants.Inputs.ServiceCatalogInputs.PROVISIONED_PRODUCT_NAME;
import static io.cloudslang.content.amazon.entities.constants.Inputs.ServiceCatalogInputs.PROVISIONING_ARTIFACT_ID;
import static io.cloudslang.content.amazon.entities.constants.Inputs.ServiceCatalogInputs.PROVISIONING_PARAMETERS;
import static io.cloudslang.content.amazon.entities.constants.Inputs.ServiceCatalogInputs.PROVISION_TOKEN;
import static io.cloudslang.content.amazon.entities.constants.Inputs.ServiceCatalogInputs.TAGS;
import static io.cloudslang.content.amazon.entities.constants.Outputs.STACK_ID;
import static io.cloudslang.content.amazon.entities.constants.Outputs.STACK_NAME;
import static io.cloudslang.content.amazon.entities.constants.Outputs.STACK_OUTPUTS;
import static io.cloudslang.content.amazon.entities.constants.Outputs.STACK_RESOURCES;
import static io.cloudslang.content.amazon.services.AmazonServiceCatalogService.describeCloudFormationStack;
import static io.cloudslang.content.amazon.services.AmazonServiceCatalogService.describeStackResources;
import static io.cloudslang.content.amazon.services.AmazonServiceCatalogService.getCloudFormationStackName;
import static io.cloudslang.content.amazon.utils.DefaultValues.COMMA;
import static io.cloudslang.content.amazon.utils.OutputsUtil.getFormattedOutputJson;
import static io.cloudslang.content.amazon.utils.OutputsUtil.getSuccessResultMapProvisionProduct;
import static io.cloudslang.content.amazon.utils.OutputsUtil.isValidJson;
import static io.cloudslang.content.amazon.utils.ServiceCatalogUtil.getStack;
import static io.cloudslang.content.amazon.utils.ServiceCatalogUtil.toArrayOfParameters;
import static io.cloudslang.content.amazon.utils.ServiceCatalogUtil.toArrayOfTags;
import static io.cloudslang.content.utils.OutputUtilities.getFailureResultsMap;
import static org.apache.commons.lang3.StringUtils.defaultIfEmpty;


public class ProvisionProductAction {

    @Action(name = "Provision Product", description = PROVISION_PRODUCT_DESCRIPTION,
            outputs = {
                    @Output(value = Outputs.RETURN_CODE, description = RETURN_CODE_DESC),
                    @Output(value = Outputs.RETURN_RESULT, description = RETURN_RESULT_DESC),
                    @Output(value = Outputs.EXCEPTION, description = EXCEPTION_DESC),
                    @Output(value = Outputs.CREATED_TIME, description = CREATED_TIME_DESC),
                    @Output(value = Outputs.PATH_ID, description = PATH_ID_DESC),
                    @Output(value = Outputs.PRODUCT_ID, description = PRODUCT_ID_DESC),
                    @Output(value = Outputs.PROVISIONED_PRODUCT_ID, description = PROVISIONED_PRODUCT_ID_DESC),
                    @Output(value = Outputs.PROVISIONED_PRODUCT_NAME, description = PROVISIONED_PRODUCT_NAME_DESC),
                    @Output(value = Outputs.PROVISIONED_PRODUCT_TYPE, description = PROVISIONED_PRODUCT_TYPE_DESC),
                    @Output(value = Outputs.PROVISIONING_ARTIFACT_ID, description = PROVISIONING_ARTIFACT_ID_OUT_DESC),
                    @Output(value = Outputs.STATUS, description = STATUS_DESC),
                    @Output(value = Outputs.STACK_ID, description = STACK_ID_DESC),
                    @Output(value = Outputs.STACK_NAME, description = STACK_NAME_DESC),
                    @Output(value = Outputs.STACK_OUTPUTS, description = STACK_OUTPUTS_DESC),
                    @Output(value = Outputs.STACK_RESOURCES, description = STACK_RESOURCES_DESC)

            },
            responses = {
                    @Response(text = Outputs.SUCCESS, field = Outputs.RETURN_CODE, value = Outputs.SUCCESS_RETURN_CODE,
                            matchType = MatchType.COMPARE_EQUAL, responseType = ResponseType.RESOLVED, description = SUCCESS_DESC),
                    @Response(text = Outputs.FAILURE, field = Outputs.RETURN_CODE, value = Outputs.FAILURE_RETURN_CODE,
                            matchType = MatchType.COMPARE_EQUAL, responseType = ResponseType.ERROR, description = FAILURE_DESC)
            }
    )
    public Map<String, String> execute(@Param(value = IDENTITY, required = true, description = IDENTITY_DESC) final String identity,
                                       @Param(value = CREDENTIAL, required = true, encrypted = true, description = CREDENTIAL_DESC) final String credential,
                                       @Param(value = PROXY_HOST, description = PROXY_HOST_DESC) final String proxyHost,
                                       @Param(value = PROXY_PORT, description = PROXY_PORT_DESC) final String proxyPort,
                                       @Param(value = PROXY_USERNAME, description = PROXY_USERNAME_DESC) final String proxyUsername,
                                       @Param(value = PROXY_PASSWORD, encrypted = true, description = PROXY_PASSWORD_DESC) final String proxyPassword,
                                       @Param(value = CONNECT_TIMEOUT, description = CONNECT_TIMEOUT_DESC) String connectTimeout,
                                       @Param(value = EXECUTION_TIMEOUT, description = EXECUTION_TIMEOUT_DESC) String execTimeout,
                                       @Param(value = POLLING_INTERVAL, description = POLLING_INTERVAL_DESC) String pollingInterval,
                                       @Param(value = ASYNC, description = ASYNC_DESC) String async,
                                       @Param(value = PRODUCT_ID, required = true, description = PRODUCT_ID_DESC) String productId,
                                       @Param(value = PROVISIONED_PRODUCT_NAME, required = true, description = PROVISIONED_PRODUCT_NAME_DESC) String provisionedProductName,
                                       @Param(value = PROVISIONING_ARTIFACT_ID, required = true, description = PROVISIONING_ARTIFACT_ID_DESC) String provisioningArtifactId,
                                       @Param(value = PROVISIONING_PARAMETERS, description = PROVISIONING_PARAMETERS_DESC) String provisioningParameters,
                                       @Param(value = DELIMITER, description = DELIMITER_DESC) String delimiter,
                                       @Param(value = TAGS, description = TAGS_DESC) String tags,
                                       @Param(value = PROVISION_TOKEN, description = PROVISION_TOKEN_DESC) String provisionTokens,
                                       @Param(value = ACCEPT_LANGUAGE, description = ACCEPT_LANGUAGE_DESC) String acceptLanguage,
                                       @Param(value = NOTIFICATION_ARNS, description = NOTIFICATION_ARNS_DESC) String notificationArns,
                                       @Param(value = PATH_ID, description = PATH_ID_DESC) String pathId,
                                       @Param(value = REGION, description = REGION_DESC) String region) {
        //Assign default values to inputs
        final String proxyPortVal = defaultIfEmpty(proxyPort, DefaultValues.PROXY_PORT);
        final String connectTimeoutVal = defaultIfEmpty(connectTimeout, DefaultValues.CONNECT_TIMEOUT);
        final String execTimeoutVal = defaultIfEmpty(execTimeout, DefaultValues.EXEC_TIMEOUT);
        final String asyncVal = defaultIfEmpty(async, DefaultValues.ASYNC);
        final String pollingIntervalVal = defaultIfEmpty(pollingInterval, DefaultValues.POLLING_INTERVAL_DEFAULT);
        final String delimiterVal = defaultIfEmpty(delimiter, COMMA);
        final String regionVal = defaultIfEmpty(region, DefaultValues.REGION);
        final String acceptLanguageVal = defaultIfEmpty(acceptLanguage, DefaultValues.ACCEPTED_LANGUAGE);

        //Validate inputs
        Validator validator = new Validator()
                .validatePort(proxyPortVal, PROXY_PORT)
                .validateInt(connectTimeoutVal, CONNECT_TIMEOUT)
                .validateInt(execTimeoutVal, EXECUTION_TIMEOUT)
                .validateBoolean(asyncVal, ASYNC);

        if (validator.hasErrors()) {
            return getFailureResultsMap(validator.getErrors());
        }

        //Variable conversions
        final Integer proxyPortImp = Integer.valueOf(proxyPortVal);
        final Integer connectTimeoutImp = Integer.valueOf(connectTimeoutVal);
        final Integer execTimeoutImp = Integer.valueOf(execTimeoutVal);
        final Long pollingIntervalImp = Long.valueOf(pollingIntervalVal);
        final Boolean asyncImp = Boolean.valueOf(asyncVal);

        try {

            final AWSServiceCatalog awsServiceCatalog = ServiceCatalogClientBuilder.getServiceCatalogClientBuilder(identity, credential,
                    proxyHost, proxyPortImp, proxyUsername, proxyPassword, connectTimeoutImp, execTimeoutImp, regionVal, asyncImp);

            final ProvisionProductResult result = AmazonServiceCatalogService.provisionProduct(provisionedProductName,
                    toArrayOfParameters(provisioningParameters, delimiterVal), productId, provisionTokens, provisioningArtifactId,
                    toArrayOfTags(tags, delimiterVal), acceptLanguageVal, notificationArns, pathId, awsServiceCatalog);


            final String cloudFormationStackName = getCloudFormationStackName(result.getRecordDetail().getRecordId(), awsServiceCatalog, pollingIntervalImp);

            final AmazonCloudFormation awsCloudFormation = CloudFormationClientBuilder.getCloudFormationClient(identity, credential,
                    proxyHost, proxyPort, proxyUsername, proxyPassword, connectTimeoutVal, execTimeoutVal, regionVal);

            List<Stack> stacks = describeCloudFormationStack(cloudFormationStackName, awsCloudFormation);

            while (getStack(stacks).getStackStatus().equals(CREATE_IN_PROGRESS)) {
                Thread.sleep(pollingIntervalImp);
                stacks = describeCloudFormationStack(cloudFormationStackName, awsCloudFormation);
            }

            if (!getStack(stacks).getStackStatus().equals(CREATE_COMPLETE)) {
                throw new RuntimeException("Stack creation failure. Reason: " + stacks.get(0).getStackStatusReason());
            }

            String stackOutputs = getFormattedOutputJson(getStack(stacks).getOutputs().toString());
            String stackResources = getFormattedOutputJson(describeStackResources(cloudFormationStackName, awsCloudFormation));

            if (!isValidJson(stackOutputs) || !isValidJson(stackResources)) {
                throw new RuntimeException("JSON output(s) could not be formatted.");
            }

            Map<String, String> results = getSuccessResultMapProvisionProduct(result);

            results.put(STACK_NAME, getStack(stacks).getStackName());
            results.put(STACK_ID, getStack(stacks).getStackId());
            results.put(STACK_OUTPUTS, stackOutputs);
            results.put(STACK_RESOURCES, stackResources);

            return results;
        } catch (Exception e) {
            return getFailureResultsMap(e);
        }
    }
}
