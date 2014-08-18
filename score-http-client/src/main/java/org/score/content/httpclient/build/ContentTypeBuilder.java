package org.score.content.httpclient.build;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.Consts;
import org.apache.http.entity.ContentType;

/**
 * Created with IntelliJ IDEA.
 * User: tusaa
 * Date: 8/12/14
 */
public class ContentTypeBuilder {
    private static String DEFAULT_CONTENT_TYPE = "text/plain";
    private static String DEFAULT_CHARACTER_SET = Consts.ISO_8859_1.name();

    private String contentType;
    private String requestCharacterSet;

    public ContentTypeBuilder setContentType(String contentType) {
        this.contentType = contentType;
        return this;
    }

    public ContentTypeBuilder setRequestCharacterSet(String requestCharacterSet) {
        if (!StringUtils.isEmpty(requestCharacterSet)) {
            this.requestCharacterSet = requestCharacterSet;
        }
        return this;
    }

    public ContentType buildContentType() {
        String contentType = this.contentType;
        String requestCharacterSet = this.requestCharacterSet;
        if (StringUtils.isEmpty(contentType)) {
            contentType = DEFAULT_CONTENT_TYPE;
            requestCharacterSet = DEFAULT_CHARACTER_SET;
        }
        ContentType parsedContentType = ContentType.parse(contentType);
        //do not override contentType provide by user
        if (!StringUtils.isEmpty(requestCharacterSet)) {
            parsedContentType = parsedContentType.withCharset(requestCharacterSet);
        }
        return parsedContentType;
    }
}
