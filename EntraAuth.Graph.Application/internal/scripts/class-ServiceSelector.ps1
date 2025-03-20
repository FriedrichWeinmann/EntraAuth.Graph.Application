class ServiceSelector {
	[string]GetService([hashtable]$ServiceMap, [string]$Name) {
		if ($ServiceMap[$Name]) { return $ServiceMap[$Name] }

		return $script:_services[$Name]
	}
	[hashtable]GetServiceMap([hashtable]$ServiceMap) {
		$map = $script:_services.Clone()
		if ($ServiceMap) {
			foreach ($pair in $ServiceMap.GetEnumerator()) {
				$map[$pair.Key] = $pair.Value
			}
		}
		return $map
	}
}