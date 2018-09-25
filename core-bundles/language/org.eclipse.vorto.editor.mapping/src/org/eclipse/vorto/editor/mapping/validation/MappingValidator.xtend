
/*******************************************************************************
* Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
*******************************************************************************/
package org.eclipse.vorto.editor.mapping.validation
//import org.eclipse.xtext.validation.Check

/**
 * Custom validation rules. 
 *
 * see http://www.eclipse.org/Xtext/documentation.html#validation
 */
class MappingValidator extends AbstractMappingValidator {


	@Check
	def checkMappingsMatchPlatform(Mapping mapping) {
		
		var targetPlatform = mapping.targetPlatform
		var mappingRules = mapping.rules
		
		if (targetPlatform == "BEL_NFC") {
			for (var i = 0; i < mappingRules.length; i++) {
				var rule = mappingRules.get(i)
				if (!(rule.target instanceof NFCTypeTarget)) {
					error("Mapping rule target" + rule.target.getType().name +  " does not match selected target platform " + mapping.targetPlatform, mapping,
						ModelPackage.Literals.MODEL__VERSION)
				}
			}
		}
	}
}
		


