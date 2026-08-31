function is_json(str) {
	try {
		const result = JSON.parse(str);
		return typeof result === 'object' && result !== null;
	} catch (e) {
		return false;
	}
}

function is_timehhmm(str) {
	const match = String(str).match(/^(\d?\d):(\d\d)$/);
	if (match) {
		const hour = parseInt(match[1], 10);
		const minute = parseInt(match[2], 10);
		if (hour >= 0 && hour <= 23 && minute >= 0 && minute <= 59) {
			return true;
		}
	}
	return false;
}

if (typeof cbi_validators !== 'undefined' && cbi_validators !== null) {
	cbi_validators['base64'] = function() {
		return isBase64(this);
	}
	cbi_validators['json'] = function() {
		return is_json(this);
	}
	cbi_validators['timehhmm'] = function() {
		return is_timehhmm(this);
	}
	cbi_validators['uuid'] = function() {
		return isUUID(this);
	}
} else {
	L.require('validation').then(function(validation) {
		validation.types['base64'] = function() {
			return this.assert(isBase64(this.value), _('Must be Base64 text!'));
		}
		validation.types['json'] = function() {
			return this.assert(is_json(this.value), _('Must be JSON text!'));
		}
		validation.types['timehhmm'] = function() {
			return this.assert(is_timehhmm(this.value), _('valid time (hh:mm)'));
		}
		validation.types['uuid'] = function() {
			return this.assert(isUUID(this.value), _('Must be UUID format!'));
		}
	});
}
