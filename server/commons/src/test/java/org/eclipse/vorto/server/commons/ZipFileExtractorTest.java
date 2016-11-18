/**
 * Copyright (c) 2015-2016 Bosch Software Innovations GmbH and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * The Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 * Bosch Software Innovations GmbH - Please refer to git log
 */
package org.eclipse.vorto.server.commons;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.apache.commons.io.IOUtils;
import org.eclipse.vorto.core.api.model.functionblock.FunctionblockModel;
import org.eclipse.vorto.core.api.model.informationmodel.InformationModel;
import org.eclipse.vorto.core.api.model.model.Model;
import org.eclipse.vorto.server.commons.MappingZipFileExtractor;
import org.eclipse.vorto.server.commons.ModelZipFileExtractor;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;

/**
 * @author Alexander Edelmann - Robert Bosch (SEA) Pte. Ltd.
 */
public class ZipFileExtractorTest {
	
	@Test
	public void testGetInformationModelFromZipFile() throws Exception {
		ModelZipFileExtractor extractor = new ModelZipFileExtractor(IOUtils.toByteArray(new ClassPathResource("models.zip").getInputStream()));
		Model model = extractor.extract("TI_SensorTag_CC2650");
		assertNotNull(model);
		assertTrue(model instanceof InformationModel);
	}
	
	@Test
	public void testGetFunctionblockFromZipFile() throws Exception {
		ModelZipFileExtractor extractor = new ModelZipFileExtractor(IOUtils.toByteArray(new ClassPathResource("models.zip").getInputStream()));
		Model model = extractor.extract("LightSensor");
		assertNotNull(model);
		assertTrue(model instanceof FunctionblockModel);
	}
	
	
	@Test
	public void testCreateMappingContextFromZipFile() throws Exception {
		MappingZipFileExtractor mappingFileExtractor = new MappingZipFileExtractor(IOUtils.toByteArray(new ClassPathResource("mappings.zip").getInputStream()));
		assertNotNull(mappingFileExtractor.extract());
	}
	
}