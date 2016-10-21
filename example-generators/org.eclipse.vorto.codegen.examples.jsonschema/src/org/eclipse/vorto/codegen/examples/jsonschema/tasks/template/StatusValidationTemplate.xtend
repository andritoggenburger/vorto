package org.eclipse.vorto.codegen.examples.jsonschema.tasks.template;

import org.eclipse.vorto.codegen.api.ITemplate;
import org.eclipse.vorto.codegen.api.InvocationContext;
import org.eclipse.vorto.core.api.model.functionblock.Status;
import org.eclipse.vorto.core.api.model.datatype.PrimitivePropertyType
import org.eclipse.vorto.core.api.model.datatype.ObjectPropertyType
import org.eclipse.vorto.codegen.examples.jsonschema.Utils
import org.eclipse.vorto.core.api.model.datatype.Entity
import org.eclipse.vorto.core.api.model.datatype.Enum

public class StatusValidationTemplate implements ITemplate<Status> {
	
	var EntityValidationTemplate entityValidationTemplate
	var EnumValidationTemplate enumValidationTemplate
	var PrimitiveTypeValidationTemplate primitiveTypeValidationTemplate
	var ConstraintTemplate constraintTemplate
	
	new(EnumValidationTemplate enumValidationTemplate,
		EntityValidationTemplate entityValidationTemplate,
		PrimitiveTypeValidationTemplate primitiveTypeValidationTemplate,
		ConstraintTemplate constraintTemplate
		
	) {
		this.enumValidationTemplate = enumValidationTemplate;
		this.primitiveTypeValidationTemplate = primitiveTypeValidationTemplate;
		this.entityValidationTemplate = entityValidationTemplate;
		this.constraintTemplate = constraintTemplate;
	}
	
	override getContent(Status status, InvocationContext invocationContext) {
				'''
			{
				"$schema": "http://json-schema.org/draft-04/schema#",
				"title": "Status Validation",
				"description": "Status Validation.",
				"type": "object",
				"properties": {
					«FOR property : status.properties SEPARATOR ','»
						«var propertyType = property.type»
						«IF propertyType instanceof PrimitivePropertyType»
							«var primitiveType = propertyType as PrimitivePropertyType»
							«IF property.isMultiplicity»
								"«property.name»": {
									"type": "array",
									"items": {
										«primitiveTypeValidationTemplate.getContent(primitiveType.type,invocationContext)»
										«Utils.getConstraintsContent(property.constraintRule, invocationContext)»
									}
								}
							«ELSE»
								"«property.name»": {
									«primitiveTypeValidationTemplate.getContent(primitiveType.type,invocationContext)»
									«Utils.getConstraintsContent(property.constraintRule, invocationContext)»
								}
							«ENDIF»
						«ELSEIF propertyType instanceof ObjectPropertyType»
							«var objectType = propertyType as ObjectPropertyType»
							«IF objectType.type instanceof Entity»
								«IF property.isMultiplicity»
									"«property.name»": {
										"type": "array",
										"items": {
											"type": "object",
											"properties": {
												«entityValidationTemplate.getContent(objectType.type as Entity,invocationContext)»
											}
										}
									}
								«ELSE»
									"«property.name»": {
										"type": "object",
										"properties": {
											«entityValidationTemplate.getContent(objectType.type as Entity,invocationContext)»
										}
									}
								«ENDIF»
							«ELSEIF objectType.type instanceof Enum»
								«IF property.isMultiplicity» 
									"«property.name»": {
										"type": "array",
										"items": {
											«enumValidationTemplate.getContent(objectType.type as Enum,invocationContext)»
										}
									}
								«ELSE»
									"«property.name»": {
										«enumValidationTemplate.getContent(objectType.type as Enum,invocationContext)»
									}
								«ENDIF»
							«ENDIF»
						«ENDIF»
					«ENDFOR»
				},
				"required" : [«FOR property : status.properties SEPARATOR ', '»"«property.name»"«ENDFOR»]
			}
		'''
	}


}
