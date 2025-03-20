class FilterBuilder {
	[System.Collections.ArrayList]$Entries = @()
	[string]$CustomFilter

	[void]Add([string]$Property, [string]$Operator, $Value) {
		$null = $this.Entries.Add(
			@{
				Property = $Property
				Operator = $Operator
				Value = $Value
			}
		)
	}
	[int]Count() {
		$myCount = $this.Entries.Count
		if ($this.CustomFilter) { $myCount++ }
		return $myCount
	}
	[string]Get() {
		$segments = foreach ($entry in $this.Entries) {
			$valueString = $entry.Value -as [string]
			if ($null -eq $entry.Value) { $valueString = "''" }
			if ($entry.Value -is [string]) {
				$valueString = "'$($entry.Value)'"
				if ($entry.Value -match '\*$' -and $entry.Operator -eq 'eq') {
					"startswith($($entry.Property), '$($entry.Value.TrimEnd('*'))')"
					continue
				}
			}
			'{0} {1} {2}' -f $entry.Property, $entry.Operator, $valueString
		}
		if ($this.CustomFilter) {
			if ($segments) { $segments = @($segments) + $this.CustomFilter }
			else { $segments = $this.CustomFilter }
		}

		return $segments -join ' and '
	}
}