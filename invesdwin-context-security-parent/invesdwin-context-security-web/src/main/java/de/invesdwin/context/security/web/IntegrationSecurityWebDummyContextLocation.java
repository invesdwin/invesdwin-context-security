package de.invesdwin.context.security.web;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.annotation.concurrent.Immutable;
import javax.inject.Named;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.apache.commons.lang3.BooleanUtils;
import org.springframework.core.io.ClassPathResource;

import de.invesdwin.context.beans.init.PreMergedContext;
import de.invesdwin.context.beans.init.locations.AConditionalContextLocation;
import de.invesdwin.context.beans.init.locations.IContextLocation;
import de.invesdwin.context.beans.init.locations.PositionedResource;
import de.invesdwin.context.beans.init.locations.position.ResourcePosition;

@Named
@Immutable
public class IntegrationSecurityWebDummyContextLocation extends AConditionalContextLocation {

    private static Boolean activated;

    @Override
    protected List<PositionedResource> getContextResourcesIfConditionSatisfied() {
        //the dummy-http-tag needs to be loaded before any /** pattern tags or else spring will throw an exception.
        return Arrays.asList(PositionedResource
                .of(new ClassPathResource("/META-INF/ctx.integration.security.web.dummy.xml"), ResourcePosition.START));
    }

    @Override
    protected boolean isConditionSatisfied() {
        if (activated != null) {
            return activated;
        } else {
            return isAnotherContextAvailableWithSecurityHttpTag();
        }
    }

    private boolean isAnotherContextAvailableWithSecurityHttpTag() {
        final Map<String, IContextLocation> mergers = PreMergedContext.getInstance()
                .getBeansOfType(IContextLocation.class);
        for (final IContextLocation merger : mergers.values()) {
            if (merger == this) {
                continue;
            }
            final List<PositionedResource> contextResources = merger.getContextResources();
            if (contextResources != null) {
                for (final PositionedResource contextResource : contextResources) {
                    if (contextResource != null) {
                        try {
                            if (containsSecurityHttpTag(contextResource)) {
                                return false;
                            }
                        } catch (XMLStreamException | IOException e) {
                            throw new RuntimeException(e);
                        }
                    }
                }
            }
        }
        return true;
    }

    private boolean containsSecurityHttpTag(final PositionedResource contextResource)
            throws XMLStreamException, IOException {
        final XMLInputFactory xif = XMLInputFactory.newInstance();
        final XMLStreamReader xsr = xif.createXMLStreamReader(contextResource.getInputStream());
        xsr.nextTag(); //beans tag skipped

        while (xsr.hasNext()) {
            if (xsr.next() == XMLStreamConstants.START_ELEMENT) {
                final String tagName = xsr.getLocalName();
                //webFragmentName
                if ("http".equalsIgnoreCase(tagName)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static void activate() {
        activated = true;
    }

    public static void deactivate() {
        activated = false;
    }

    public static void reset() {
        activated = null;
    }

    public static boolean isActivated() {
        return BooleanUtils.isTrue(activated);
    }

    public static boolean isDeactivated() {
        return BooleanUtils.isFalse(activated);
    }

}
