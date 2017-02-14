package io.cloudslang.content.amazon.factory.helpers;

import io.cloudslang.content.amazon.entities.aws.VolumeAttachmentStatus;
import io.cloudslang.content.amazon.entities.aws.VolumeFilter;
import io.cloudslang.content.amazon.entities.aws.VolumeStatus;
import io.cloudslang.content.amazon.entities.aws.VolumeType;
import io.cloudslang.content.amazon.entities.constants.Constants;
import io.cloudslang.content.amazon.entities.inputs.InputsWrapper;
import io.cloudslang.content.amazon.utils.InputsUtil;

import java.util.HashMap;
import java.util.Map;

import static io.cloudslang.content.amazon.entities.constants.Constants.AwsParams.*;
import static io.cloudslang.content.amazon.entities.constants.Constants.Miscellaneous.*;
import static io.cloudslang.content.amazon.entities.constants.Constants.Values.ONE;
import static io.cloudslang.content.amazon.entities.constants.Constants.Values.START_INDEX;
import static io.cloudslang.content.amazon.entities.constants.Inputs.InstanceInputs.FILTER_NAMES_STRING;
import static io.cloudslang.content.amazon.entities.constants.Inputs.InstanceInputs.FILTER_VALUES_STRING;
import static java.lang.String.valueOf;
import static org.apache.commons.lang3.ArrayUtils.isNotEmpty;
import static org.apache.commons.lang3.StringUtils.EMPTY;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

/**
 * Created by Mihai Tusa.
 * 9/9/2016.
 */
public class VolumeUtils {
    private static final String ATTACHMENT_STATUS_FILTER = "attachment.status";
    private static final String STATUS_FILTER = "status";
    private static final String VOLUME_TYPE_FILTER = "volume-type";
    private static final String NOT_RELEVANT_KEY_STRING = "-1";
    private static final String AVAILABILITY_ZONE = "AvailabilityZone";
    private static final String DEVICE = "Device";
    private static final String KMS_KEY_ID = "KmsKeyId";
    private static final String SIZE = "Size";
    public static final String NEXT_TOKEN = "NextToken";
    public static final String MAX_RESULTS = "MaxResults";

    public Map<String, String> getAttachVolumeQueryParamsMap(InputsWrapper wrapper) {
        return getAttachDetachVolumeCommonQueryParamsMap(wrapper);
    }

    public Map<String, String> getCreateVolumeQueryParamsMap(InputsWrapper wrapper) {
        Map<String, String> queryParamsMap = new HashMap<>();
        InputsUtil.setCommonQueryParamsMap(queryParamsMap, wrapper.getCommonInputs().getAction(),
                wrapper.getCommonInputs().getVersion());
        queryParamsMap.put(AVAILABILITY_ZONE, wrapper.getCustomInputs().getAvailabilityZone());

        String volumeType = NOT_RELEVANT.equals(wrapper.getCustomInputs().getVolumeType()) ? STANDARD :
                wrapper.getCustomInputs().getVolumeType();
        queryParamsMap.put(VOLUME_TYPE, volumeType);

        InputsUtil.setOptionalMapEntry(queryParamsMap, KMS_KEY_ID, wrapper.getCustomInputs().getKmsKeyId(),
                isNotBlank(wrapper.getCustomInputs().getKmsKeyId()));
        InputsUtil.setOptionalMapEntry(queryParamsMap, SIZE, wrapper.getVolumeInputs().getSize(),
                isNotBlank(wrapper.getVolumeInputs().getSize()));
        InputsUtil.setOptionalMapEntry(queryParamsMap, SNAPSHOT_ID, wrapper.getVolumeInputs().getSnapshotId(),
                isNotBlank(wrapper.getVolumeInputs().getSnapshotId()));
        InputsUtil.setOptionalMapEntry(queryParamsMap, ENCRYPTED, String.valueOf(ONE), wrapper.getVolumeInputs().isEncrypted());
        InputsUtil.setOptionalMapEntry(queryParamsMap, IOPS, wrapper.getVolumeInputs().getIops(),
                !NOT_RELEVANT.equals(wrapper.getVolumeInputs().getIops()));

        return queryParamsMap;
    }

    public Map<String, String> getDetachVolumeQueryParamsMap(InputsWrapper wrapper) {
        Map<String, String> queryParamsMap = getAttachDetachVolumeCommonQueryParamsMap(wrapper);
        InputsUtil.setOptionalMapEntry(queryParamsMap, FORCE, String.valueOf(wrapper.getVolumeInputs().isForce()),
                wrapper.getVolumeInputs().isForce());

        return queryParamsMap;
    }

    public Map<String, String> getDeleteVolumeQueryParamsMap(InputsWrapper wrapper) {
        Map<String, String> queryParamsMap = new HashMap<>();
        InputsUtil.setCommonQueryParamsMap(queryParamsMap, wrapper.getCommonInputs().getAction(), wrapper.getCommonInputs().getVersion());
        queryParamsMap.put(VOLUME_ID, wrapper.getCustomInputs().getVolumeId());

        return queryParamsMap;
    }

    public Map<String, String> getDescribeVolumesQueryParamsMap(InputsWrapper wrapper) {
        Map<String, String> queryParamsMap = new HashMap<>();
        InputsUtil.setCommonQueryParamsMap(queryParamsMap, wrapper.getCommonInputs().getAction(), wrapper.getCommonInputs().getVersion());

        InputsUtil.setOptionalMapEntry(queryParamsMap, MAX_RESULTS, wrapper.getVolumeInputs().getMaxResults(),
                !NOT_RELEVANT.equalsIgnoreCase(wrapper.getVolumeInputs().getMaxResults()));
        InputsUtil.setOptionalMapEntry(queryParamsMap, NEXT_TOKEN, wrapper.getVolumeInputs().getNextToken(),
                isNotBlank(wrapper.getVolumeInputs().getNextToken()));

        setDescribeVolumesQueryParamsFilter(queryParamsMap, wrapper);

        return queryParamsMap;
    }

    private Map<String, String> getAttachDetachVolumeCommonQueryParamsMap(InputsWrapper wrapper) {
        Map<String, String> queryParamsMap = new HashMap<>();
        InputsUtil.setCommonQueryParamsMap(queryParamsMap, wrapper.getCommonInputs().getAction(), wrapper.getCommonInputs().getVersion());
        queryParamsMap.put(DEVICE, wrapper.getVolumeInputs().getDeviceName());
        queryParamsMap.put(INSTANCE_ID, wrapper.getCustomInputs().getInstanceId());
        queryParamsMap.put(VOLUME_ID, wrapper.getCustomInputs().getVolumeId());

        return queryParamsMap;
    }

    private void setDescribeVolumesQueryParamsFilter(Map<String, String> queryParamsMap, InputsWrapper wrapper) {
        final String[] filterNamesArray = InputsUtil.getArrayWithoutDuplicateEntries(wrapper.getVolumeInputs().getFilterNamesString(),
                FILTER_NAMES_STRING, wrapper.getCommonInputs().getDelimiter());
        final String[] filterValuesArray = InputsUtil.getStringsArray(wrapper.getVolumeInputs().getFilterValuesString(), EMPTY,
                wrapper.getCommonInputs().getDelimiter());
        InputsUtil.validateAgainstDifferentArraysLength(filterNamesArray, filterValuesArray, FILTER_NAMES_STRING, FILTER_VALUES_STRING);
        if (isNotEmpty(filterNamesArray) && isNotEmpty(filterValuesArray)) {
            for (int index = START_INDEX; index < filterNamesArray.length; index++) {
                String filterName = VolumeFilter.getVolumeFilter(filterNamesArray[index]);
                queryParamsMap.put(getFilterNameKey(index), filterName);
                setFilterValues(queryParamsMap, filterName, filterValuesArray[index], index);
            }
        }
    }

    private void setFilterValues(Map<String, String> queryParamsMap, String filterName, String filterValues, int index) {
        String[] valuesArray = InputsUtil.getStringsArray(filterValues, Constants.Miscellaneous.EMPTY, PIPE_DELIMITER);
        if (isNotEmpty(valuesArray)) {
            for (int counter = START_INDEX; counter < valuesArray.length; counter++) {
                if (!NOT_RELEVANT.equalsIgnoreCase(getFilterValue(filterName, valuesArray[counter]))
                        || !NOT_RELEVANT_KEY_STRING.equals(getFilterValue(filterName, valuesArray[counter]))) {
                    queryParamsMap.put(getFilterValueKey(index, counter),
                            getFilterValue(filterName, valuesArray[counter].toLowerCase()));
                }
            }
        }
    }

    private String getFilterValue(String filterName, String filterValue) {
        switch (filterName) {
            case ATTACHMENT_STATUS_FILTER:
                return VolumeAttachmentStatus.getValue(filterValue);
            case STATUS_FILTER:
                return VolumeStatus.getValue(filterValue);
            case VOLUME_TYPE_FILTER:
                return VolumeType.getValue(filterValue);
            default:
                return filterValue;
        }
    }

    private String getFilterNameKey(int index) {
        return FILTER + DOT + valueOf(index + ONE) + DOT + NAME;
    }

    private String getFilterValueKey(int index, int counter) {
        return FILTER + DOT + valueOf(index + ONE) + DOT + VALUE + DOT + valueOf(counter + ONE);
    }
}
