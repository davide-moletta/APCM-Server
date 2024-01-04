package it.unitn.APCM.ACME.ServerCommon;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;

public class JSONToArray extends ArrayList<String> {

	public JSONToArray(String str) throws JsonProcessingException {
		if (str != null) {
			ObjectMapper objectMapper = new ObjectMapper();
			TypeReference<ArrayList<String>> typeReference = new TypeReference<>() {};
			try {
				this.addAll(objectMapper.readValue(str, typeReference));
			} catch (JsonProcessingException e) {
				throw new RuntimeException(e);
			}
		} else {
			this.clear();
		}

	}

}
