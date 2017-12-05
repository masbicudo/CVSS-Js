"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var undef;
var GroupName;
(function (GroupName) {
    GroupName["Base"] = "Base";
    GroupName["Temporal"] = "Temporal";
    GroupName["Environmental"] = "Environmental";
})(GroupName = exports.GroupName || (exports.GroupName = {}));
/** CVSS2 Represents CVSS 2 metrics for a vulnerability.
 *
 *  This code is implemented according to the specification
 *  of the CVSS found at:
 *
 *    https://www.first.org/cvss/v2/guide
 */
var CVSS2 = /** @class */ (function () {
    function CVSS2() {
        // Base
        this.AV = undef; // Attack Vector         [N,A,L]
        this.AC = undef; // Attack Complexity     [H,M,L]
        this.Au = undef; // Authentication        [M,S,N]
        this.C = undef; // Confidentiality       [N,P,C]
        this.I = undef; // Integrity             [N,P,C]
        this.A = undef; // Availability          [N,P,C]
        // temporal
        this.E = 'ND'; // Exploit Code Maturity [U,POC,F,H,ND]
        this.RL = 'ND'; // Remediation Level     [OF,TF,W,U,ND]
        this.RC = 'ND'; // Report Confidence     [UC,UR,C,ND]
        // environmental
        this.CR = 'ND'; // Confidentiality Req. [L,M,H,ND]
        this.IR = 'ND'; // Integrity Req.       [L,M,H,ND]
        this.AR = 'ND'; // Availability Req.    [L,M,H,ND]
        this.CDP = 'ND'; // Collateral Damage Potential [N,L,LM,MH,H,ND]
        this.TD = 'ND'; // Target Distribution         [N,L,M,H,ND]
        this.RoundUnit = 0.1;
    }
    CVSS2.parseMetricsString = function (input_string, varargin) {
        // Parses a CVSS stringParses a CVSS string
        //   This function reads the CVSS string in input_string
        //   and generates a CVSS instance containig the numeric parameters.
        var opts = { 'IgnoreRequired': false, 'Map': CVSS2.lookup_table };
        for (var k in varargin)
            if (varargin.hasOwnProperty(k))
                opts[k] = varargin[k];
        var M = new CVSS2();
        M = CVSS2.fillCVSSWithParsedString(M, input_string);
        M = CVSS2.replaceMetrics(M, opts.Map);
        // checking required values
        if (!opts.IgnoreRequired) {
            if (M.AV == undef)
                throw new Error('CVSS2 parameter AV is required');
            if (M.AC == undef)
                throw new Error('CVSS2 parameter AC is required');
            if (M.Au == undef)
                throw new Error('CVSS2 parameter Au is required');
            if (M.C == undef)
                throw new Error('CVSS2 parameter C is required');
            if (M.I == undef)
                throw new Error('CVSS2 parameter I is required');
            if (M.A == undef)
                throw new Error('CVSS2 parameter A is required');
        }
        return M;
    };
    CVSS2.parseCVSSString = function (input_string) {
        // Parses a CVSS string
        //   This function reads the CVSS string in input_string
        //   and generates a CVSS instance containig the string parameters.
        var M = CVSS2.fillCVSSWithParsedString(new CVSS2(), input_string);
        return M;
    };
    CVSS2.fillCVSSWithParsedString = function (M, input_string) {
        // Parses a CVSS string
        //   This function reads the CVSS string in input_string
        //   and fills a CVSS instance with the string parameters.
        M = M.clone();
        // converting the input_string to a struct
        var input_string1 = input_string.replace(' ', '');
        var pieces = input_string1.split('/');
        for (var i = 0; i < pieces.length; i++) {
            var kv = pieces[i].split(':');
            if (CVSS2.isprop(kv[0])) {
                M[kv[0]] = kv[1].toUpperCase();
            }
        }
        Object.freeze(M);
        return M;
    };
    CVSS2.checkFieldSupported = function (field) {
        if (CVSS2.prop_names.indexOf(field) < 0)
            throw new Error("CVSS 2 does not support a field named " + field);
    };
    CVSS2.replaceMetrics = function (M, map) {
        M = M.clone();
        function getChecked(obj, field, names) {
            if (names.indexOf(field) < 0)
                throw new Error("Invalid value name: " + field);
            return obj[field];
        }
        var getNames = Object.getOwnPropertyNames;
        var lt = CVSS2.lookup_table;
        // replacing string with numbers in the struct fields
        if (typeof (M.AV) == 'string' && M.AV)
            M.AV = getChecked(map.AV, M.AV, getNames(lt.AV));
        if (typeof (M.AC) == 'string' && M.AC)
            M.AC = getChecked(map.AC, M.AC, getNames(lt.AC));
        if (typeof (M.Au) == 'string' && M.Au)
            M.Au = getChecked(map.Au, M.Au, getNames(lt.Au));
        if (typeof (M.C) == 'string' && M.C)
            M.C = getChecked(map.C, M.C, getNames(lt.C));
        if (typeof (M.I) == 'string' && M.I)
            M.I = getChecked(map.I, M.I, getNames(lt.I));
        if (typeof (M.A) == 'string' && M.A)
            M.A = getChecked(map.A, M.A, getNames(lt.A));
        // Temporal
        if (typeof (M.E) == 'string' && M.E)
            M.E = getChecked(map.E, M.E, getNames(lt.E));
        if (typeof (M.RL) == 'string' && M.RL)
            M.RL = getChecked(map.RL, M.RL, getNames(lt.RL));
        if (typeof (M.RC) == 'string' && M.RC)
            M.RC = getChecked(map.RC, M.RC, getNames(lt.RC));
        // Environmental
        if (typeof (M.CR) == 'string' && M.CR)
            M.CR = getChecked(map.CR, M.CR, getNames(lt.CR));
        if (typeof (M.IR) == 'string' && M.IR)
            M.IR = getChecked(map.IR, M.IR, getNames(lt.IR));
        if (typeof (M.AR) == 'string' && M.AR)
            M.AR = getChecked(map.AR, M.AR, getNames(lt.AR));
        if (typeof (M.CDP) == 'string' && M.CDP)
            M.CDP = getChecked(map.CDP, M.CDP, getNames(lt.CDP));
        if (typeof (M.TD) == 'string' && M.TD)
            M.TD = getChecked(map.TD, M.TD, getNames(lt.TD));
        Object.freeze(M);
        return M;
    };
    CVSS2.revertMetrics = function (M, map) {
        M = M.clone();
        for (var k in map) {
            CVSS2.checkFieldSupported(k);
            if (map.hasOwnProperty(k)) {
                var val = M[k];
                if (CVSS2.isNumeric(val)) {
                    var tbl2 = map[k];
                    for (var k2 in tbl2)
                        if (tbl2.hasOwnProperty(k2) && tbl2[k2] == val)
                            M[k] = k2;
                }
            }
        }
        Object.freeze(M);
        return M;
    };
    CVSS2.convertToCvssString = function (M, varargin) {
        var opts = { 'IgnoreNotDefined': false, 'Map': CVSS2.lookup_table };
        for (var k in varargin)
            if (varargin.hasOwnProperty(k))
                opts[k] = varargin[k];
        var str = '';
        for (var _i = 0, _a = CVSS2.prop_names; _i < _a.length; _i++) {
            var k = _a[_i];
            var val = M[k];
            if (typeof val == "undefined" || val === null)
                val = "ND";
            if (CVSS2.isNumeric(val)) {
                var tbl2 = opts.Map[k];
                for (var k2 in tbl2)
                    if (tbl2[k2] == val)
                        val = k2;
            }
            var ignore = val === "ND" && opts.IgnoreNotDefined && !CVSS2.map_required[k];
            if (!ignore) {
                if (!CVSS2.lookup_table[k].hasOwnProperty(val))
                    val = "";
                if (str)
                    str += "/";
                str += k + ':' + val;
            }
        }
        return str;
    };
    CVSS2.round = function (u, n) {
        return (Math.round(1 / u * n)) * u;
    };
    CVSS2.isprop = function (propName) {
        return !CVSS2.prop_names.every(function (x) { return x != propName; });
    };
    CVSS2.isNumeric = function (n) {
        return !isNaN(parseFloat(n)) && isFinite(n);
    };
    CVSS2.prototype.withDefaultTemporal = function () {
        return this.fillParse(CVSS2.default_temporal);
    };
    CVSS2.prototype.withBestTemporal = function () {
        return this.fillParse(CVSS2.best_temporal);
    };
    CVSS2.prototype.withWorstTemporal = function () {
        return this.fillParse(CVSS2.worst_temporal);
    };
    CVSS2.prototype.withDefaultEnvironmental = function () {
        return this.fillParse(CVSS2.default_environmental);
    };
    CVSS2.prototype.withBestEnvironmental = function () {
        return this.fillParse(CVSS2.best_environmental);
    };
    CVSS2.prototype.withWorstEnvironmental = function () {
        return this.fillParse(CVSS2.worst_environmental);
    };
    CVSS2.prototype.baseScore = function () {
        // BaseScore = round_to_1_decimal(((0.6*Impact)+(0.4*Exploitability)-1.5)*f(Impact))
        // f(impact) = 0 if Impact=0, 1.176 otherwise
        var Impact = this.impactSubscore();
        var retval = this.internalBaseScore(Impact);
        return retval;
    };
    CVSS2.prototype.internalBaseScore = function (Impact) {
        // BaseScore = round_to_1_decimal(((0.6*Impact)+(0.4*Exploitability)-1.5)*f(Impact))
        // f(impact) = 0 if Impact=0, 1.176 otherwise
        if (Impact == 0)
            return 0;
        else {
            var Exploitability = this.exploitabilitySubscore();
            return CVSS2.round(this.RoundUnit, (0.6 * Impact + 0.4 * Exploitability - 1.5) * 1.176);
        }
    };
    CVSS2.prototype.impactSubscore = function () {
        // Impact = 10.41*(1-(1-ConfImpact)*(1-IntegImpact)*(1-AvailImpact))
        var M = this;
        var c = M.C;
        var i = M.I;
        var a = M.A;
        var retval = 10.41 * (1 - ((1 - c) * (1 - i) * (1 - a)));
        return retval;
    };
    CVSS2.prototype.exploitabilitySubscore = function () {
        // Exploitability = 20* AccessVector*AccessComplexity*Authentication
        var M = this;
        var av = M.AV;
        var ac = M.AC;
        var au = M.Au;
        var retval = 20 * av * ac * au;
        return retval;
    };
    CVSS2.prototype.temporalScore = function () {
        // TemporalScore = round_to_1_decimal(BaseScore*Exploitability*RemediationLevel*ReportConfidence)
        var M = this;
        var e = M.E;
        var rl = M.RL;
        var rc = M.RC;
        var retval = CVSS2.round(M.RoundUnit, this.baseScore() * e * rl * rc);
        return retval;
    };
    CVSS2.prototype.environmentalScore = function () {
        // EnvironmentalScore = round_to_1_decimal((AdjustedTemporal+
        // (10-AdjustedTemporal)*CollateralDamagePotential)*TargetDistribution)
        var M = this;
        var cdp = M.CDP;
        var td = M.TD;
        var AdjustedTemporal = this.adjustedTemporalSubscore();
        var retval = CVSS2.round(M.RoundUnit, (AdjustedTemporal + (10 - AdjustedTemporal) * cdp) * td);
        return retval;
    };
    CVSS2.prototype.adjustedTemporalSubscore = function () {
        // AdjustedTemporal = TemporalScore recomputed with the BaseScores Impact sub-equation replaced with the AdjustedImpact equation
        var M = this;
        var e = M.E;
        var rl = M.RL;
        var rc = M.RC;
        var Impact = this.adjustedImpactSubscore();
        var retval = CVSS2.round(M.RoundUnit, this.internalBaseScore(Impact) * e * rl * rc);
        return retval;
    };
    CVSS2.prototype.adjustedImpactSubscore = function () {
        // AdjustedImpact = min(10,10.41*(1-(1-ConfImpact*ConfReq)*(1-IntegImpact*IntegReq)
        //                  *(1-AvailImpact*AvailReq)))
        var M = this;
        var c = M.C;
        var cr = M.CR;
        var i = M.I;
        var ir = M.IR;
        var a = M.A;
        var ar = M.AR;
        return Math.min(10, 10.41 * (1 - (1 - c * cr) * (1 - i * ir) * (1 - a * ar)));
    };
    CVSS2.prototype.fillParse = function (input_string) {
        // Reparse returns a new CVSS2 object with additional metrics from
        // the given string.
        var O = CVSS2.fillCVSSWithParsedString(this, input_string);
        O = CVSS2.replaceMetrics(O, CVSS2.lookup_table);
        return O;
    };
    CVSS2.prototype.withStrings = function () {
        // Converts this CVSS parameters to their equivalent string representations when possible.
        return CVSS2.revertMetrics(this, CVSS2.lookup_table);
    };
    CVSS2.prototype.toString = function (varargin) {
        // Converts this CVSS object to it's equivalent string representation.
        return CVSS2.convertToCvssString(this, varargin);
    };
    CVSS2.prototype.getFullInfo = function () {
        var O = new CVSS2();
        this.forEach(function (d, o) { O[d.name] = d; });
        var clone = CVSS2.replaceMetrics(this, CVSS2.lookup_table);
        var Impact = clone.adjustedImpactSubscore();
        O.scores = {
            baseScore: clone.baseScore(),
            environmentalScore: clone.environmentalScore(),
            temporalScore: clone.temporalScore(),
            exploitabilitySubscore: clone.exploitabilitySubscore(),
            internalBaseScore: clone.internalBaseScore(Impact),
            adjustedImpactSubscore: Impact,
            adjustedTemporalSubscore: clone.adjustedTemporalSubscore(),
            impactSubscore: clone.impactSubscore(),
        };
        Object.freeze(O);
        return O;
    };
    CVSS2.prototype.forEach = function (f, varargin) {
        var M = this;
        var names = CVSS2.prop_names;
        for (var i = 0; i < names.length; i++) {
            var k = names[i];
            var val = M[k];
            var fullStringValue = [];
            var numericValue = NaN;
            var stringValue = [];
            var subtable = CVSS2.lookup_table[k];
            if (typeof val == 'string') {
                stringValue = [val];
                numericValue = subtable[val];
            }
            else if (typeof val == "number") {
                numericValue = val;
                for (var k2 in subtable)
                    if (subtable.hasOwnProperty(k2) && subtable[k2] == val)
                        stringValue.push(k2);
            }
            if (stringValue)
                fullStringValue = stringValue.map(function (x) { return CVSS2.map_value_names[k][x]; });
            var data = {
                'name': k,
                'value': val,
                'fullName': CVSS2.map_prop_names[k],
                fullStringValue: fullStringValue,
                numericValue: numericValue,
                stringValue: stringValue,
            };
            f(data, varargin);
        }
    };
    CVSS2.prototype.clone = function () {
        var M = new CVSS2();
        M.AV = this.AV;
        M.AC = this.AC;
        M.Au = this.Au;
        M.C = this.C;
        M.I = this.I;
        M.A = this.A;
        // Temporal
        M.E = this.E;
        M.RL = this.RL;
        M.RC = this.RC;
        // Environmental
        M.CR = this.CR;
        M.IR = this.IR;
        M.AR = this.AR;
        M.CDP = this.CDP;
        M.TD = this.TD;
        // note: DO NOT FREEZE THE CLONED OBJECT
        // this method is intended to make editable clones
        return M;
    };
    CVSS2.getAllParamInfos = function () {
        var result = [];
        var grps = CVSS2.map_prop_groups;
        for (var k in grps)
            if (grps.hasOwnProperty(k))
                result.push(CVSS2.getParamInfo(k));
        return result;
    };
    CVSS2.getParamInfo = function (name) {
        if (!CVSS2.isprop(name))
            throw new Error("Invalid CVSS 2 parameter name: " + name);
        var fullName = CVSS2.map_prop_names[name];
        var fullValueName = CVSS2.map_value_names[name];
        var values = CVSS2.lookup_table[name];
        var vals = [];
        for (var k in values)
            if (values.hasOwnProperty(k))
                vals.push({
                    fullStringValue: fullValueName[k],
                    numericValue: values[k],
                    stringValue: k,
                });
        return {
            name: name,
            fullName: fullName,
            group: CVSS2.map_prop_groups[name],
            values: vals
        };
    };
    CVSS2.lookup_table = {
        'AV': { 'N': 1.000, 'A': 0.646, 'L': 0.395 },
        'AC': { 'L': 0.710, 'M': 0.610, 'H': 0.350 },
        'Au': { 'M': 0.450, 'S': 0.560, 'N': 0.704 },
        'C': { 'C': 0.660, 'P': 0.275, 'N': 0.000 },
        'I': { 'C': 0.660, 'P': 0.275, 'N': 0.000 },
        'A': { 'C': 0.660, 'P': 0.275, 'N': 0.000 },
        'E': { 'ND': 1.00, 'H': 1.00, 'F': 0.95, 'POC': 0.90, 'U': 0.85 },
        'RL': { 'ND': 1.00, 'U': 1.00, 'W': 0.95, 'TF': 0.90, 'OF': 0.87 },
        'RC': { 'ND': 1.00, 'C': 1.00, 'UR': 0.95, 'UC': 0.90 },
        'CR': { 'ND': 1.00, 'H': 1.51, 'M': 1.00, 'L': 0.50 },
        'IR': { 'ND': 1.00, 'H': 1.51, 'M': 1.00, 'L': 0.50 },
        'AR': { 'ND': 1.00, 'H': 1.51, 'M': 1.00, 'L': 0.50 },
        'CDP': { 'ND': 0.00, 'N': 0.00, 'L': 0.10, 'LM': 0.30, 'MH': 0.40, 'H': 0.50 },
        'TD': { 'ND': 1.00, 'N': 0.00, 'L': 0.25, 'M': 0.75, 'H': 1.00 }
    };
    CVSS2.map_prop_names = {
        'AV': 'Attack Vector',
        'AC': 'Attack Complexity',
        'Au': 'Authentication',
        'C': 'Confidentiality',
        'I': 'Integrity',
        'A': 'Availability',
        'E': 'Exploit Code Maturity',
        'RL': 'Remediation Level',
        'RC': 'Report Confidence',
        'CR': 'Confidentiality Req.',
        'IR': 'Integrity Req.',
        'AR': 'Availability Req.',
        'CDP': 'Collateral Damage Potential',
        'TD': 'Target Distribution',
    };
    CVSS2.map_prop_groups = {
        'AV': GroupName.Base,
        'AC': GroupName.Base,
        'Au': GroupName.Base,
        'C': GroupName.Base,
        'I': GroupName.Base,
        'A': GroupName.Base,
        'E': GroupName.Temporal,
        'RL': GroupName.Temporal,
        'RC': GroupName.Temporal,
        'CR': GroupName.Environmental,
        'IR': GroupName.Environmental,
        'AR': GroupName.Environmental,
        'CDP': GroupName.Environmental,
        'TD': GroupName.Environmental,
    };
    CVSS2.map_value_names = {
        'AV': { 'N': 'Network', 'A': 'Adjacent Network', 'L': 'Local' },
        'AC': { 'H': 'High', 'M': 'Medium', 'L': 'Low' },
        'Au': { 'M': 'Multiple', 'S': 'Single', 'N': 'None' },
        'C': { 'C': 'Complete', 'P': 'Partial', 'N': 'None' },
        'I': { 'C': 'Complete', 'P': 'Partial', 'N': 'None' },
        'A': { 'C': 'Complete', 'P': 'Partial', 'N': 'None' },
        'E': { 'ND': 'Not Defined', 'H': 'High', 'F': 'Functional', 'POC': 'Proof-of-Concept', 'U': 'Unproven' },
        'RL': { 'ND': 'Not Defined', 'U': 'Unavailable', 'W': 'Workaround', 'TF': 'Temporary Fix', 'OF': 'Official Fix' },
        'RC': { 'ND': 'Not Defined', 'C': 'Confirmed', 'UR': 'Uncorroborated', 'UC': 'Unconfirmed' },
        'CR': { 'ND': 'Not Defined', 'H': 'High', 'M': 'Medium', 'L': 'Low' },
        'IR': { 'ND': 'Not Defined', 'H': 'High', 'M': 'Medium', 'L': 'Low' },
        'AR': { 'ND': 'Not Defined', 'H': 'High', 'M': 'Medium', 'L': 'Low' },
        'CDP': { 'ND': 'Not Defined', 'N': 'None', 'H': 'High', 'MH': 'Medium-High', 'LM': 'Low-Medium', 'L': 'Low' },
        'TD': { 'ND': 'Not Defined', 'N': 'None', 'H': 'High', 'M': 'Medium', 'L': 'Low' }
    };
    CVSS2.map_required = {
        'AV': 1,
        'AC': 1,
        'Au': 1,
        'C': 1,
        'I': 1,
        'A': 1,
    };
    CVSS2.prop_names = ['AV', 'AC', 'Au', 'C', 'I', 'A', 'E', 'RL', 'RC', 'CR', 'IR', 'AR', 'CDP', 'TD'];
    CVSS2.group_names = ['Base', 'Temporal', 'Environmental'];
    CVSS2.default_temporal = 'E:ND/RL:ND/RC:ND';
    CVSS2.best_temporal = 'E:U/RL:OF/RC:UC';
    CVSS2.worst_temporal = 'E:H/RL:U/RC:C';
    CVSS2.default_environmental = 'CR:ND/IR:ND/AR:ND/CDP:ND/TD:ND';
    CVSS2.best_environmental = 'CR:L/IR:L/AR:L/CDP:N/TD:N';
    CVSS2.worst_environmental = 'CR:H/IR:H/AR:H/CDP:H/TD:H';
    return CVSS2;
}());
exports.CVSS2 = CVSS2;
