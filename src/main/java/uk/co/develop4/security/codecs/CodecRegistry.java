/* 
 * =============================================================================
 * 
 *  Copyright (c) 2014, The Develop4 Technologies Ltd (http://www.develop4.co.uk)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * =============================================================================
 */
package uk.co.develop4.security.codecs;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class CodecRegistry {
	
	private static final Map<Namespace,Codec> codecRepository;
	
	static {
		codecRepository = new ConcurrentHashMap<Namespace,Codec>();
	}

	public void put(Codec codec) {
		codecRepository.put(codec.getNamespace(), codec);
    }

    public Optional<Codec> get(Namespace id) {
        return Optional.ofNullable(codecRepository.get(id));
    }

	public Collection<Codec> values() {
		return codecRepository.values();
	}

}
