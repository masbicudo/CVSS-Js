var undef : any;

export interface IDeserializeOptions {
    IgnoreRequired: false;
    Map: IMap<any>;
}

export interface ISerializeOptions {
    IgnoreNotDefined: false;
    Map: IMap<any>;
}

export interface IFullFieldInfo {
    name: string;
    value: string|number;
    fullName: string;
    numericValue: number;
    stringValue: string[];
    fullStringValue: string[];
}

export interface IParamValueInfo {
    stringValue: string;
    numericValue: number;
    fullStringValue: string;
}

export interface IParamInfo {
    name: string;
    fullName: string;
    group: GroupName;
    values: IParamValueInfo[];
}

export interface IMap<TValue> {
    'AV': { 'N': TValue,  'A': TValue,  'L': TValue },
    'AC': { 'L': TValue,  'M': TValue,  'H': TValue },
    'Au': { 'M': TValue,  'S': TValue,  'N': TValue },
    'C': { 'C': TValue,  'P': TValue,  'N': TValue },
    'I': { 'C': TValue,  'P': TValue,  'N': TValue },
    'A': { 'C': TValue,  'P': TValue,  'N': TValue },

    'E': {'ND': TValue,  'H': TValue,  'F': TValue,'POC': TValue,  'U': TValue},
    'RL': {'ND': TValue,  'U': TValue,  'W': TValue, 'TF': TValue, 'OF': TValue},
    'RC': {'ND': TValue,  'C': TValue, 'UR': TValue, 'UC': TValue},

    'CR': {'ND': TValue,  'H': TValue,  'M': TValue,  'L': TValue},
    'IR': {'ND': TValue,  'H': TValue,  'M': TValue,  'L': TValue},
    'AR': {'ND': TValue,  'H': TValue,  'M': TValue,  'L': TValue},
    'CDP': {'ND': TValue,  'N': TValue,  'L': TValue, 'LM': TValue, 'MH': TValue,  'H': TValue},
    'TD': {'ND': TValue,  'N': TValue,  'L': TValue,  'M': TValue,  'H': TValue}
}

const F_AV = 1 << 0;
const F_AC = 1 << 1;
const F_AU = 1 << 2;
const F_C  = 1 << 3;
const F_CR = 1 << 9;
const F_I  = 1 << 4;
const F_IR = 1 << 10;
const F_A  = 1 << 5;
const F_AR = 1 << 11;
const F_E = 1 << 6;
const F_RL = 1 << 7;
const F_RC = 1 << 8;
const F_CDP = 1 << 12;
const F_TD = 1 << 13;
const F_IMPACT = F_C|F_I|F_A;
const F_EXPLOITABILITY = F_AV|F_AC|F_AU;
const F_INTERNAL_BASE = F_EXPLOITABILITY;
const F_BASE = F_IMPACT|F_INTERNAL_BASE;
const F_ADJUSTED_IMPACT = F_C|F_CR|F_I|F_IR|F_A|F_AR;
const F_ADJUSTED_TEMPORAL = F_E|F_RL|F_RC|F_ADJUSTED_IMPACT|F_INTERNAL_BASE;
const F_ENVIRONMENTAL = F_CDP|F_TD|F_ADJUSTED_TEMPORAL;
const F_TEMPORAL = F_E|F_RL|F_RC|F_BASE;

export enum GroupName {
    "Base" = "Base",
    "Temporal" = "Temporal",
    "Environmental" = "Environmental",
}

/** CVSS2 Represents CVSS 2 metrics for a vulnerability.
 * 
 *  This code is implemented according to the specification
 *  of the CVSS found at:
 * 
 *    https://www.first.org/cvss/v2/guide
 */
export class CVSS2 {
    static readonly lookup_table = {
        'AV': { 'N':1.000,  'A':0.646,  'L':0.395 },
        'AC': { 'L':0.710,  'M':0.610,  'H':0.350 },
        'Au': { 'M':0.450,  'S':0.560,  'N':0.704 },
        'C': { 'C':0.660,  'P':0.275,  'N':0.000 },
        'I': { 'C':0.660,  'P':0.275,  'N':0.000 },
        'A': { 'C':0.660,  'P':0.275,  'N':0.000 },

        'E': {'ND':1.00,  'H':1.00,  'F':0.95,'POC':0.90,  'U':0.85},
        'RL': {'ND':1.00,  'U':1.00,  'W':0.95, 'TF':0.90, 'OF':0.87},
        'RC': {'ND':1.00,  'C':1.00, 'UR':0.95, 'UC':0.90},

        'CR': {'ND':1.00,  'H':1.51,  'M':1.00,  'L':0.50},
        'IR': {'ND':1.00,  'H':1.51,  'M':1.00,  'L':0.50},
        'AR': {'ND':1.00,  'H':1.51,  'M':1.00,  'L':0.50},
        'CDP': {'ND':0.00,  'N':0.00,  'L':0.10, 'LM':0.30, 'MH':0.40,  'H':0.50},
        'TD': {'ND':1.00,  'N':0.00,  'L':0.25,  'M':0.75,  'H':1.00}}

    static readonly map_prop_names = {
        'AV': 'Attack Vector',
        'AC': 'Attack Complexity',
        'Au': 'Authentication',
        'C': 'Confidentiality Impact',
        'I': 'Integrity Impact',
        'A': 'Availability Impact',

        'E': 'Exploitability',
        'RL': 'Remediation Level',
        'RC': 'Report Confidence',

        'CR': 'Confidentiality Requirement',
        'IR': 'Integrity Requirement',
        'AR': 'Availability Requirement',
        'CDP': 'Collateral Damage Potential',
        'TD': 'Target Distribution',
        }

    static readonly map_prop_groups : {[k:string]:GroupName} = {
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
        }

    static readonly map_value_names = {
        'AV': { 'N': 'Network',  'A': 'Adjacent Network', 'L': 'Local'},
        'AC': { 'H': 'High',     'M': 'Medium',  'L': 'Low'},
        'Au': { 'M': 'Multiple', 'S': 'Single',  'N': 'None'},
        'C': { 'C': 'Complete', 'P': 'Partial', 'N': 'None'},
        'I': { 'C': 'Complete', 'P': 'Partial', 'N': 'None'},
        'A': { 'C': 'Complete', 'P': 'Partial', 'N': 'None'},

        'E': {'ND': 'Not Defined', 'H': 'High',        'F': 'Functional', 'POC': 'Proof-of-Concept', 'U': 'Unproven'},
        'RL': {'ND': 'Not Defined', 'U': 'Unavailable', 'W': 'Workaround', 'TF': 'Temporary Fix', 'OF': 'Official Fix'},
        'RC': {'ND': 'Not Defined', 'C': 'Confirmed',   'UR': 'Uncorroborated', 'UC': 'Unconfirmed'},

        'CR': {'ND': 'Not Defined',              'H': 'High',  'M': 'Medium',                          'L': 'Low'},
        'IR': {'ND': 'Not Defined',              'H': 'High',  'M': 'Medium',                          'L': 'Low'},
        'AR': {'ND': 'Not Defined',              'H': 'High',  'M': 'Medium',                          'L': 'Low'},
        'CDP': {'ND': 'Not Defined', 'N': 'None', 'H': 'High', 'MH': 'Medium-High', 'LM': 'Low-Medium', 'L': 'Low'},
        'TD': {'ND': 'Not Defined', 'N': 'None', 'H': 'High',  'M': 'Medium',                          'L': 'Low'}}

    static readonly map_required = {
        'AV': 1,
        'AC': 1,
        'Au': 1,
        'C': 1,
        'I': 1,
        'A': 1,
        }

    static readonly prop_names : string[] = [ 'AV', 'AC', 'Au', 'C', 'I', 'A', 'E', 'RL', 'RC', 'CR', 'IR', 'AR','CDP', 'TD' ];
    static readonly group_names : string[] = [ 'Base', 'Temporal', 'Environmental' ];

    static readonly default_temporal : string = 'E:ND/RL:ND/RC:ND';
    static readonly best_temporal : string = 'E:U/RL:OF/RC:UC';
    static readonly worst_temporal : string = 'E:H/RL:U/RC:C';

    static readonly default_environmental : string = 'CR:ND/IR:ND/AR:ND/CDP:ND/TD:ND';
    static readonly best_environmental : string = 'CR:L/IR:L/AR:L/CDP:N/TD:N';
    static readonly worst_environmental : string = 'CR:H/IR:H/AR:H/CDP:H/TD:H';
    
    // Base
    public AV : string|number = undef;      // Attack Vector         [N,A,L]
    public AC : string|number = undef;      // Attack Complexity     [H,M,L]
    public Au : string|number = undef;      // Authentication        [M,S,N]
    public C  : string|number = undef;      // Confidentiality       [N,P,C]
    public I  : string|number = undef;      // Integrity             [N,P,C]
    public A  : string|number = undef;      // Availability          [N,P,C]
    
    // temporal
    public E   : string|number = 'ND'; // Exploit Code Maturity [U,POC,F,H,ND]
    public RL  : string|number = 'ND'; // Remediation Level     [OF,TF,W,U,ND]
    public RC  : string|number = 'ND'; // Report Confidence     [UC,UR,C,ND]
    
    // environmental
    public CR  : string|number = 'ND'; // Confidentiality Req. [L,M,H,ND]
    public IR  : string|number = 'ND'; // Integrity Req.       [L,M,H,ND]
    public AR  : string|number = 'ND'; // Availability Req.    [L,M,H,ND]

    public CDP  : string|number = 'ND'; // Collateral Damage Potential [N,L,LM,MH,H,ND]
    public TD   : string|number = 'ND'; // Target Distribution         [N,L,M,H,ND]

    public RoundUnit : number = 0.1;
    
    public static parseMetricsString( input_string : string, varargin : IDeserializeOptions ) : CVSS2 {
        // Parses a CVSS stringParses a CVSS string
        //   This function reads the CVSS string in input_string
        //   and generates a CVSS instance containig the numeric parameters.
        var opts : IDeserializeOptions = { 'IgnoreRequired': false, 'Map': CVSS2.lookup_table };
        for (var k in varargin)
            if (varargin.hasOwnProperty(k))
                ( opts as any )[k] = ( varargin as any )[k];

        var M : CVSS2 = new CVSS2();
        M = CVSS2.fillCVSSWithParsedString( M, input_string );
        M = CVSS2.replaceMetrics( M, opts.Map );
        
        // checking required values
        if (!opts.IgnoreRequired) {
            if (M.AV == undef) throw new Error('CVSS2 parameter AV is required');
            if (M.AC == undef) throw new Error('CVSS2 parameter AC is required');
            if (M.Au == undef) throw new Error('CVSS2 parameter Au is required');
            if (M.C  == undef) throw new Error('CVSS2 parameter C is required') ;
            if (M.I  == undef) throw new Error('CVSS2 parameter I is required') ;
            if (M.A  == undef) throw new Error('CVSS2 parameter A is required') ;
        }

        return M;
    }
    public static parseCVSSString( input_string : string ) : CVSS2 {
        // Parses a CVSS string
        //   This function reads the CVSS string in input_string
        //   and generates a CVSS instance containig the string parameters.

        var M = CVSS2.fillCVSSWithParsedString( new CVSS2(), input_string );
        return M;
    }
    public static fillCVSSWithParsedString( M : CVSS2, input_string : string ) : CVSS2 {
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
                (M as any)[kv[0]] = kv[1].toUpperCase();
            }
        }
        Object.freeze(M);
        return M;
    }
    
    private static checkFieldSupported(field:string) {
        if (!CVSS2.isprop(field))
            throw new Error("Invalid CVSS 2 parameter name " + field);
    }

    public static replaceMetrics( M : CVSS2, map : IMap<number> ) : CVSS2 {
        M = M.clone();

        function getChecked(obj : {[k:string]:number}, field: any, names:string[]) : number {
            if (names.indexOf(field) < 0)
                throw new Error("Invalid value name: " + field);
            return obj[field];
        }

        var getNames = Object.getOwnPropertyNames;
        var lt = CVSS2.lookup_table;
        // replacing string with numbers in the struct fields
        if (typeof(M.AV) == 'string' && M.AV)  M.AV  = getChecked(map.AV, M.AV, getNames(lt.AV));
        if (typeof(M.AC) == 'string' && M.AC)  M.AC  = getChecked(map.AC, M.AC, getNames(lt.AC));
        if (typeof(M.Au) == 'string' && M.Au)  M.Au  = getChecked(map.Au, M.Au, getNames(lt.Au));
        if (typeof(M.C)  == 'string' && M.C)   M.C   = getChecked(map.C , M.C , getNames(lt.C ));
        if (typeof(M.I)  == 'string' && M.I)   M.I   = getChecked(map.I , M.I , getNames(lt.I ));
        if (typeof(M.A)  == 'string' && M.A)   M.A   = getChecked(map.A , M.A , getNames(lt.A ));

        // Temporal
        if (typeof(M.E)  == 'string' && M.E)   M.E   = getChecked(map.E , M.E , getNames(lt.E ));
        if (typeof(M.RL) == 'string' && M.RL)  M.RL  = getChecked(map.RL, M.RL, getNames(lt.RL));
        if (typeof(M.RC) == 'string' && M.RC)  M.RC  = getChecked(map.RC, M.RC, getNames(lt.RC));

        // Environmental
        if (typeof(M.CR) == 'string' && M.CR)  M.CR  = getChecked(map.CR, M.CR, getNames(lt.CR));
        if (typeof(M.IR) == 'string' && M.IR)  M.IR  = getChecked(map.IR, M.IR, getNames(lt.IR));
        if (typeof(M.AR) == 'string' && M.AR)  M.AR  = getChecked(map.AR, M.AR, getNames(lt.AR));

        if (typeof(M.CDP)== 'string' && M.CDP) M.CDP = getChecked(map.CDP, M.CDP, getNames(lt.CDP));
        if (typeof(M.TD) == 'string' && M.TD)  M.TD  = getChecked(map.TD, M.TD, getNames(lt.TD));

        Object.freeze(M);
        return M;
    }

    public static revertMetrics( M: CVSS2, map : IMap<any> ) {
        M = M.clone();

        for (var k in map) {
            CVSS2.checkFieldSupported(k);
            if (map.hasOwnProperty(k)) {
                var val = (M as any)[k];
                if (CVSS2.isNumeric(val)) {
                    var tbl2 = (map as any)[k];
                    for (var k2 in tbl2)
                        if (tbl2.hasOwnProperty(k2) && tbl2[k2] == val)
                            (M as any)[k] = k2;
                }
            }
        }

        Object.freeze(M);
        return M;
    }

    public static convertToCvssString( M : CVSS2, varargin : ISerializeOptions ) : string {
        var opts = {'IgnoreNotDefined': false, 'Map': CVSS2.lookup_table};
        for (var k in varargin)
            if (varargin.hasOwnProperty(k))
                (opts as any)[k] = (varargin as any)[k];

        var str = '';

        for (var k of CVSS2.prop_names) {
            var val = (M as any)[k];
            if (typeof val == "undefined" || val === null) val = "ND";
            if (CVSS2.isNumeric(val)) {
                var tbl2 = (opts.Map as any)[k];
                for (var k2 in tbl2)
                    if (tbl2[k2] == val)
                        val = k2;
            }
            var ignore = val === "ND" && opts.IgnoreNotDefined && !(CVSS2.map_required as any)[k];
            if (!ignore) {
                if (!(CVSS2.lookup_table as any)[k].hasOwnProperty(val)) val = "";
                if (str) str += "/";
                str += k+':'+val;
            }
        }
        return str;
    }

    public static round(u:number, n:number) {
        return (Math.round(1/u*n))*u;
    }
    
    public static isprop(propName : string) {
        return CVSS2.prop_names.indexOf(propName) >= 0;
    }


    public static isNumeric(n:any) : boolean {
      return !isNaN(parseFloat(n as string)) && isFinite(n as number);
    }

    public withDefaultTemporal() : CVSS2 {
        return this.fillParse( CVSS2.default_temporal );
    }
    public withBestTemporal() : CVSS2 {
        return this.fillParse( CVSS2.best_temporal );
    }
    public withWorstTemporal() : CVSS2 {
        return this.fillParse( CVSS2.worst_temporal );
    }
    public withDefaultEnvironmental() : CVSS2 {
        return this.fillParse( CVSS2.default_environmental );
    }
    public withBestEnvironmental() : CVSS2 {
        return this.fillParse( CVSS2.best_environmental );
    }
    public withWorstEnvironmental() : CVSS2 {
        return this.fillParse( CVSS2.worst_environmental );
    }

    public baseScore(fast? : boolean) : number {
        // BaseScore = round_to_1_decimal(((0.6*Impact)+(0.4*Exploitability)-1.5)*f(Impact))
        // f(impact) = 0 if Impact=0, 1.176 otherwise
        var M = this as CVSS2;
        if (!fast && !(M.hasMetrics() & F_BASE)) M = M.withMetrics();
        var Impact = M.impactSubscore(true);
        var retval = M.internalBaseScore(Impact, true);
        return retval;
    }

    public internalBaseScore(Impact : number, fast? : boolean) : number {
        // BaseScore = round_to_1_decimal(((0.6*Impact)+(0.4*Exploitability)-1.5)*f(Impact))
        // f(impact) = 0 if Impact=0, 1.176 otherwise
        if (Impact == 0)
            return 0;
        else {
            var Exploitability = this.exploitabilitySubscore(fast);
            return CVSS2.round(this.RoundUnit, (0.6*Impact + 0.4*Exploitability - 1.5)*1.176);
        }
    }

    public impactSubscore(fast? : boolean) : number {
        // Impact = 10.41*(1-(1-ConfImpact)*(1-IntegImpact)*(1-AvailImpact))
        var M = this as CVSS2;
        if (!fast && !(M.hasMetrics() & F_IMPACT)) M = M.withMetrics();
        var c = M.C as number;
        var i = M.I as number;
        var a = M.A as number;
        var retval = 10.41*(1 - ((1 - c)*(1 - i)*(1 - a)));
        return retval;
    }
    
    public exploitabilitySubscore(fast? : boolean) : number {
        // Exploitability = 20* AccessVector*AccessComplexity*Authentication
        var M = this as CVSS2;
        if (!fast && !(M.hasMetrics() & F_EXPLOITABILITY)) M = M.withMetrics();
        var av = M.AV as number;
        var ac = M.AC as number;
        var au = M.Au as number;
        var retval = 20 * av * ac * au;
        return retval;
    }
    
    public temporalScore(fast? : boolean) : number {
        // TemporalScore = round_to_1_decimal(BaseScore*Exploitability*RemediationLevel*ReportConfidence)
        var M = this as CVSS2;
        if (!fast && !(M.hasMetrics() & F_TEMPORAL)) M = M.withMetrics();
        var e = M.E as number;
        var rl = M.RL as number;
        var rc = M.RC as number;
        var retval = CVSS2.round(M.RoundUnit, M.baseScore(true) * e * rl * rc);
        return retval;
    }
    
    public environmentalScore(fast? : boolean) : number {
        // EnvironmentalScore = round_to_1_decimal((AdjustedTemporal+
        // (10-AdjustedTemporal)*CollateralDamagePotential)*TargetDistribution)
        var M = this as CVSS2;
        if (!fast && !(M.hasMetrics() & F_ENVIRONMENTAL)) M = M.withMetrics();
        var cdp = M.CDP as number;
        var td = M.TD as number;
        var AdjustedTemporal = M.adjustedTemporalSubscore(true);
        var retval = CVSS2.round(M.RoundUnit, (AdjustedTemporal + (10 - AdjustedTemporal)*cdp)*td);
        return retval;
    }
    
    public adjustedTemporalSubscore(fast? : boolean) : number {
        // AdjustedTemporal = TemporalScore recomputed with the BaseScores Impact sub-equation replaced with the AdjustedImpact equation
        var M = this as CVSS2;
        if (!fast && !(M.hasMetrics() & F_ADJUSTED_TEMPORAL)) M = M.withMetrics();
        var e = M.E as number;
        var rl = M.RL as number;
        var rc = M.RC as number;
        var Impact = M.adjustedImpactSubscore(true);
        var retval = CVSS2.round(M.RoundUnit, M.internalBaseScore(Impact) * e * rl * rc);
        return retval;
    }
    
    public adjustedImpactSubscore(fast? : boolean) : number {
        // AdjustedImpact = min(10,10.41*(1-(1-ConfImpact*ConfReq)*(1-IntegImpact*IntegReq)
        //                  *(1-AvailImpact*AvailReq)))
        var M = this as CVSS2;
        if (!fast && !(M.hasMetrics() & F_ADJUSTED_IMPACT)) M = M.withMetrics();
        var c = M.C as number;
        var cr = M.CR as number;
        var i = M.I as number;
        var ir = M.IR as number;
        var a = M.A as number;
        var ar = M.AR as number;
        return Math.min(10, 10.41*(1 - (1 - c*cr)*(1 - i*ir)*(1 - a*ar)));
    }
    
    public fillParse( input_string : string ) : CVSS2 {
        // Reparse returns a new CVSS2 object with additional metrics from
        // the given string.
        var O = CVSS2.fillCVSSWithParsedString( this, input_string );
        O = O.withMetrics();
        return O;
    }

    public withMetrics() : CVSS2 {
        var O = CVSS2.replaceMetrics( this, CVSS2.lookup_table );
        return O;
    }
    
    public withStrings() : CVSS2 {
        // Converts this CVSS parameters to their equivalent string representations when possible.
        return CVSS2.revertMetrics( this, CVSS2.lookup_table );
    }

    /**
     * Returns the number of numeric metrics found within this CVSS2 object.
     */
    public hasMetrics() : number {
        var f = 1, r = 0;
        var lt = CVSS2.lookup_table;
        for(var k in lt)
            if (lt.hasOwnProperty(k)) {
                if (typeof (lt as any)[k] == "number") r |= f;
                f *= 2;
            }
        return r;
    }
    
    public toString( varargin : ISerializeOptions ) : string {
        // Converts this CVSS object to it's equivalent string representation.
        return CVSS2.convertToCvssString( this, varargin );
    }
    
    public getFullInfo() : CVSS2 {
        var O = new CVSS2();
        this.forEach((d,o)=>{ (O as any)[d.name] = d; });
        var clone = this.withMetrics();
        var Impact = clone.adjustedImpactSubscore(true);
        (O as any).scores = {
            baseScore: clone.baseScore(true),
            environmentalScore: clone.environmentalScore(true),
            temporalScore: clone.temporalScore(true),
            exploitabilitySubscore: clone.exploitabilitySubscore(true),
            internalBaseScore: clone.internalBaseScore(Impact, true),
            adjustedImpactSubscore: Impact,
            adjustedTemporalSubscore: clone.adjustedTemporalSubscore(true),
            impactSubscore: clone.impactSubscore(true),
        }
        Object.freeze(O);
        return O;
    }

    public forEach( f : ( d:IFullFieldInfo, o:any ) => void, varargin?: any ) {
        var M = this;
        var names = CVSS2.prop_names;
        for (var i = 0; i < names.length; i++) {
            var k = names[i];
            var val : string|number = (M as any)[k];
            var fullStringValue : string[] = [];
            var numericValue : number = NaN;
            var stringValue : string[] = [];
            var subtable = (CVSS2.lookup_table as any)[k];
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
            if (stringValue) fullStringValue = stringValue.map(x => (CVSS2.map_value_names as any)[k][x]);
            var data : IFullFieldInfo = {
                'name': k,
                'value': val,
                'fullName': (CVSS2.map_prop_names as {[k:string]:string})[k],
                fullStringValue,
                numericValue,
                stringValue,
            };
            f(data, varargin);
        }
    }

    public clone() : CVSS2 {
        var M = new CVSS2();
        M.AV  = this.AV;
        M.AC  = this.AC;
        M.Au  = this.Au;
        M.C   = this.C;
        M.I   = this.I;
        M.A   = this.A;

        // Temporal
        M.E   = this.E;
        M.RL  = this.RL;
        M.RC  = this.RC;

        // Environmental
        M.CR  = this.CR;
        M.IR  = this.IR;
        M.AR  = this.AR;

        M.CDP = this.CDP;
        M.TD  = this.TD;

        // note: DO NOT FREEZE THE CLONED OBJECT
        // this method is intended to make editable clones
        return M;
    }

    public static getAllParamInfos( ) : IParamInfo[] {
        var result = [];
        const grps = CVSS2.map_prop_groups;
        for(var k in grps)
            if (grps.hasOwnProperty(k))
                result.push(CVSS2.getParamInfo(k));
        return result;
    }

    public static getParamInfo( name: string ) : IParamInfo {
        CVSS2.checkFieldSupported(name);
        var fullName = (CVSS2.map_prop_names as any)[name];
        var fullValueName = (CVSS2.map_value_names as any)[name];
        var values = (CVSS2.lookup_table as any)[name];

        var vals : IParamValueInfo[] = [];
        for(var k in values)
            if (values.hasOwnProperty(k))
                vals.push({
                    fullStringValue: fullValueName[k],
                    numericValue: values[k],
                    stringValue: k,
                });

        return {
            name,
            fullName,
            group: CVSS2.map_prop_groups[name],
            values: vals
        }
    }

    public static assign( M : CVSS2, D : CVSS2 ) : CVSS2 {
        return Object.freeze((<any>Object).assign(M.clone(), D));
    }
}