import argparse
import jinja2
from typing import Any, Optional, Union
import asn1tools
import regex


# "[NASA]" or "[NASA]LaunchVehicle" or "[ABC]123"
PASCAL_CAP_SEQUENCE_RE = regex.compile("^([\\p{Lu}]+)($|[\\p{Lu}][\\p{Ll}]|\\p{N})")

# "[Cow]Launcher" or "[sheep]Launcher"
PASCAL_WORD_RE = regex.compile("^([\\p{Lu}]?[\\p{Ll}]+)")

# "[123]ABC"
PASCAL_DIGITS_RE = regex.compile("^([\\p{N}]+)")


TEMPLATE = """
{%- macro rustify_sequence(type_name, type_def) -%}
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct {{ type_name|pascal|rust_identifier }} {
    {%- for member in type_def.members if member is not none %}
    {% if member.type == "SEQUENCE OF" %}#[serde(default)] {% endif %}pub {{ member.name|snake|rust_identifier }}: {{ member|rust_type(type_name) }},
    {%- endfor %}
}
impl {{ type_name|pascal|rust_identifier }} {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::DecodingError<'a>>> {
        {%- set ns = namespace(optional_index=0) %}
        {%- if type_def|sequence_is_extensible %}
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        {%- endif %}
        {%- if type_def.members|count_optional > 0 %}
        let (rest, optional_bits) = crate::asn1_uper::decode_bools(rest, {{ type_def.members|count_optional }})?;
        {%- endif %}
        {%- for member in type_def.members if member is not none %}
            {%- if member.get("optional", false) %}
                {%- if member.type == "SEQUENCE OF" %}
                    {#- do an empty sequence instead #}
        let (rest, {{ member.name|snake|rust_identifier }}) = if optional_bits[{{ ns.optional_index }}] {
            {{ member|rust_deserialize_call(type_name) }}
        } else {
            (rest, Vec::new())
        };
                {%- else %}
        let (rest, {{ member.name|snake|rust_identifier }}) = if optional_bits[{{ ns.optional_index }}] {
            let (rest, value) = {{ member|rust_deserialize_call(type_name) }};
            (rest, Some(value))
        } else {
            (rest, None)
        };
                {%- endif %}
                {%- set ns.optional_index = ns.optional_index + 1 %}
            {%- elif "default" in member %}
        let (rest, {{ member.name|snake|rust_identifier }}) = if optional_bits[{{ ns.optional_index }}] {
            {{ member|rust_deserialize_call(type_name) }}
        } else {
            let default_value = {{ member|rust_default_value }};
            (rest, default_value)
        };
                {%- set ns.optional_index = ns.optional_index + 1 %}
            {%- else %}
        let (rest, {{ member.name|snake|rust_identifier }}) = {{ member|rust_deserialize_call(type_name) }};
            {%- endif %}
        {%- endfor %}
        let sequence = Self {
            {%- for member in type_def.members if member is not none %}
            {{ member.name|snake|rust_identifier }},
            {%- endfor %}
        };
        Ok((rest, sequence))
    }

    pub fn write_uper(&self, uper_buf: &mut Vec<bool>) -> Result<(), crate::asn1_uper::EncodingError> {
        {%- if type_def|sequence_is_extensible %}
        crate::asn1_uper::encode_bool(uper_buf, false);
        {%- endif %}
        {%- for member in type_def.members if member is not none %}
            {%- if member.get("optional", false) %}
                {%- if member.type == "SEQUENCE OF" %}
        crate::asn1_uper::encode_bool(uper_buf, self.{{ member.name|snake|rust_identifier }}.len() > 0);
                {%- else %}
        crate::asn1_uper::encode_bool(uper_buf, self.{{ member.name|snake|rust_identifier }}.is_some());
                {%- endif %}
            {%- elif "default" in member %}
        crate::asn1_uper::encode_bool(uper_buf, self.{{ member.name|snake|rust_identifier }} != {{ member|rust_default_value }});
            {%- endif %}
        {%- endfor %}
        {%- for member in type_def.members if member is not none %}
            {%- if member.get("optional", false) %}
                {%- if member.type == "SEQUENCE OF" %}
        if self.{{ member.name|snake|rust_identifier }}.len() > 0 {
            {{ member|rust_serialize_call(type_name) }};
        }
                {%- else %}
        if let Some(opt_val) = &self.{{ member.name|snake|rust_identifier }} {
            {%- set opt_member = member|dict_replacing(name="opt_val") %}
            {{ opt_member|rust_serialize_call(type_name, self_prefix=None, deref=True) }};
        }
                {%- endif %}
            {%- elif "default" in member %}
        if self.{{ member.name|snake|rust_identifier }} != {{ member|rust_default_value }} {
            {{ member|rust_serialize_call(type_name) }};
        }
            {%- else %}
        {{ member|rust_serialize_call(type_name) }};
            {%- endif %}
        {%- endfor %}
        Ok(())
    }
}
{#- and now, the inline choice definitions #}
{%- for member in type_def.members if member is not none and member.type == "CHOICE" %}
{{ rustify_choice(type_name|pascal + member.name|pascal, member) }}
{%- endfor %}
{%- endmacro -%}

{%- macro rustify_enumerated(type_name, type_def) -%}
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
pub enum {{ type_name|pascal|rust_identifier }} {
    {%- for kvp in type_def["values"] if kvp is not none %}
    {{ kvp[0]|pascal|rust_identifier }} = {{ kvp[1] }},
    {%- endfor %}
}
impl {{ type_name|pascal|rust_identifier }} {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::DecodingError<'a>>> {
        {%- if type_def|enum_is_extensible %}
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        {%- endif %}
        {%- if type_def|enum_base_option_count > 1 %}
        let (rest, value_index) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short({{ type_def|enum_base_option_count - 1 }}) })?;
        let enum_value = match value_index.try_to_usize().expect("failed to decode enumerated value to usize") {
            {#- the data is encoded as the index, not as the value! #}
            {%- for kvp in type_def["values"] if kvp is not none %}
            {{ loop.index0 }} => Self::{{ kvp[0]|pascal|rust_identifier }},
            {%- endfor %}
            other => panic!("unexpected {{ type_name|pascal|rust_identifier }} value {}", other),
        };
        Ok((rest, enum_value))
        {%- else %}
            {#- an enumeration with a single option is never explicitly encoded #}
            {%- for kvp in type_def["values"] if kvp is not none %}
        Ok((rest, Self::{{ kvp[0]|pascal|rust_identifier }}))
            {%- endfor %}
        {%- endif %}
    }

    pub fn write_uper(&self, uper_buf: &mut Vec<bool>) -> Result<(), crate::asn1_uper::EncodingError> {
        {%- if type_def|enum_is_extensible %}
        crate::asn1_uper::encode_bool(uper_buf, false);
        {%- endif %}
        {#- an enumeration with a single option is never explicitly encoded #}
        {%- if type_def|enum_base_option_count > 1 %}
        let integer_value = match self {
            {#- the data is encoded as the index, not as the value! #}
            {%- for kvp in type_def["values"] if kvp is not none %}
            Self::{{ kvp[0]|pascal|rust_identifier }} => crate::asn1_uper::Integer::from_short({{ loop.index0 }}),
            {%- endfor %}
        };
        crate::asn1_uper::encode_integer(uper_buf, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short({{ type_def|enum_base_option_count - 1 }}) }, &integer_value)?;
        {%- endif %}
        Ok(())
    }
}
{%- endmacro -%}

{%- macro rustify_choice(type_name, type_def) -%}
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum {{ type_name|pascal|rust_identifier }} {
    {%- for member in type_def.members if member is not none %}
    {{ member.name|pascal|rust_identifier }}({{ member.type|pascal|rust_identifier }}),
    {%- endfor %}
}
impl {{ type_name|pascal|rust_identifier }} {
    pub fn try_from_uper<'a>(rest: &'a [bool]) -> Result<(&'a [bool], Self), nom::Err<crate::asn1_uper::DecodingError<'a>>> {
        {%- if type_def|choice_is_extensible %}
        let (rest, is_extended) = crate::asn1_uper::decode_bool(rest)?;
        if is_extended {
            panic!("cannot currently handle extensibility");
        }
        {%- endif %}
        {%- if type_def|choice_base_option_count > 1 %}
        let (mut rest, value_index) = crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short({{ type_def|choice_base_option_count }}) })?;
        let choice_value = match value_index.try_to_usize().expect("failed to decode enumerated value to usize") {
            {#- the data is encoded as the index, not as the value! #}
            {%- for member in type_def.members if member is not none %}
            {{ loop.index0 }} => {
                let (new_rest, inner_value) = {{ member.type|rust_deserialize_call(type_name) }};
                rest = new_rest;
                Self::{{ member.name|pascal|rust_identifier }}(inner_value)
            },
            {%- endfor %}
            other => panic!("unexpected {{ type_name|pascal|rust_identifier }} value {}", other),
        };
        Ok((rest, choice_value))
        {%- else %}
            {#- a choice with a single option is never explicitly encoded #}
            {%- for member in type_def.members if member is not none %}
        let (rest, inner_value) = {{ member.type|rust_deserialize_call(type_name) }};
        Ok((rest, Self::{{ member.name|pascal|rust_identifier }}(inner_value)))
            {%- endfor %}
        {%- endif %}
    }

    pub fn write_uper(&self, uper_buf: &mut Vec<bool>) -> Result<(), crate::asn1_uper::EncodingError> {
        {%- if type_def|choice_is_extensible %}
        crate::asn1_uper::encode_bool(uper_buf, false);
        {%- endif %}
        {#- a choice with a single option is never explicitly encoded #}
        {%- if type_def|choice_base_option_count > 1 %}
        match self {
            {%- for member in type_def.members if member is not none %}
            Self::{{ member.name|pascal|rust_identifier }}(inner_value) => {
                let index = crate::asn1_uper::Integer::from_short({{ loop.index0 }});
                crate::asn1_uper::encode_integer(uper_buf, &crate::asn1_uper::WholeNumberConstraint::Constrained { min: crate::asn1_uper::Integer::from_short(0), max: crate::asn1_uper::Integer::from_short({{ type_def|choice_base_option_count }}) }, &index)?;
                {{ {"type": member.type, "name": "inner_value"}|rust_serialize_call(self_prefix=None) }};
            },
            {%- endfor %}
        };
        {%- endif %}
        Ok(())
    }
}
{%- endmacro -%}

{%- if type_def.type == "SEQUENCE" -%}{{ rustify_sequence(type_name, type_def) }}
{%- elif type_def.type == "ENUMERATED" -%}{{ rustify_enumerated(type_name, type_def) }}
{%- elif type_def.type == "CHOICE" -%}{{ rustify_choice(type_name, type_def) }}
{%- else -%}{{ raise_value_error("Cannot handle type " + type_def.type + " for " + type_name) }}
{%- endif -%}
"""


def name_to_pieces(name: str) -> list[str]:
    if "_" in name:
        # assume snake_case
        return name.split("_")
    elif "-" in name:
        # assume kebab-case
        return name.split("-")
    else:
        # assume PascalCase or camelCase
        pieces = []

        i = 0
        while name[i:]:
            matched = False
            for pattern in [PASCAL_CAP_SEQUENCE_RE, PASCAL_DIGITS_RE, PASCAL_WORD_RE]:
                m = pattern.match(name[i:])
                if m is not None:
                    pieces.append(m.group(1))
                    i += len(pieces[-1])
                    matched = True
                    break

            if not matched:
                raise ValueError(f"don't know what to do with {name[i:]}")

        return pieces


def to_pascal_case(name: str) -> str:
    pieces = name_to_pieces(name)
    return "".join(p.title() for p in pieces)

def to_camel_case(name: str) -> str:
    pieces = name_to_pieces(name)
    return "".join(p.lower() if i == 0 else p.title() for (i, p) in enumerate(pieces))

def to_kebab_case(name: str) -> str:
    pieces = name_to_pieces(name)
    return "-".join(p.lower() for p in pieces)

def to_snake_case(name: str) -> str:
    pieces = name_to_pieces(name)
    return "_".join(p.lower() for p in pieces)

def rust_identifier(name: str) -> str:
    if name == "type":
        return name + "_"
    return name

def dict_replacing(dictionary, **kvps):
    ret = dict(dictionary)
    for key, value in kvps.items():
        ret[key] = value
    return ret


def to_rust_type(type_def: dict[str, Any], parent_type: Optional[str] = None) -> str:
    type_name = type_def["type"]
    if type_name == "SEQUENCE OF":
        member_type = to_rust_type(type_def["element"])
        return f"Vec<{member_type}>"
    if type_name == "CHOICE":
        # inline choice -- construct the name
        return to_pascal_case(parent_type) + to_pascal_case(type_def["name"])

    if type_name == "INTEGER":
        inner_type = "crate::asn1_uper::Integer"
    elif type_name == "OCTET STRING":
        inner_type = "Vec<u8>"
    elif type_name in ("IA5String", "UTF8String"):
        inner_type = "String"
    elif type_name == "BOOLEAN":
        inner_type = "bool"
    else:
        inner_type = to_pascal_case(type_name)

    if type_def.get("optional", False):
        return f"Option<{inner_type}>"
    else:
        return inner_type


def string_size_constraint(type_def: dict[str, Any]) -> str:
    size = type_def.get("size", None)
    if size is not None:
        if isinstance(size[0], tuple):
            (min_size, max_size) = size[0]
        else:
            min_size = max_size = size[0]
        return f"Constrained {{ min: crate::asn1_uper::Integer::from_short({min_size}), max: crate::asn1_uper::Integer::from_short({max_size}) }}"
    return "Unconstrained"


def rust_deserialize_call(member: Union[dict[str, Any], str], parent_type: Optional[str] = None) -> str:
    if isinstance(member, str):
        member = {"type": member}
    type_name = member["type"]
    if type_name == "INTEGER":
        constraints = member.get("restricted-to", None)
        if constraints is not None:
            (int_min, int_max) = constraints[0]
            constraint_string = f"Constrained {{ min: crate::asn1_uper::Integer::from_short({int_min}), max: crate::asn1_uper::Integer::from_short({int_max}) }}"
        # TODO: semi-constrained?
        else:
            constraint_string = "Unconstrained"
        return f"crate::asn1_uper::decode_integer(rest, &crate::asn1_uper::WholeNumberConstraint::{constraint_string})?"
    elif type_name == "OCTET STRING":
        size_constraint = string_size_constraint(member)
        return f"crate::asn1_uper::decode_octet_string(rest, &crate::asn1_uper::WholeNumberConstraint::{size_constraint})?"
    elif type_name == "BOOLEAN":
        return "crate::asn1_uper::decode_bool(rest)?"
    elif type_name == "UTF8String":
        size_constraint = string_size_constraint(member)
        lines = ["{"]
        lines.append(f"    let (rest, octet_string) = crate::asn1_uper::decode_octet_string(rest, &crate::asn1_uper::WholeNumberConstraint::{size_constraint})?;")
        lines.append("    crate::asn1_uper::octet_string_to_utf8(rest, octet_string)?")
        lines.append("}")
        return "\n".join(lines)
    elif type_name == "IA5String":
        size_constraint = string_size_constraint(member)
        lines = ["{"]
        lines.append(f"    let (rest, octet_string) = crate::asn1_uper::decode_ia5_string(rest, &crate::asn1_uper::WholeNumberConstraint::{size_constraint})?;")
        lines.append("    crate::asn1_uper::octet_string_to_utf8(rest, octet_string)?")
        lines.append("}")
        return "\n".join(lines)
    elif type_name == "SEQUENCE OF":
        # TODO: handle length constraints
        lines = ["{"]
        lines.append("    let (mut rest, length_integer) = crate::asn1_uper::decode_length(rest, &crate::asn1_uper::WholeNumberConstraint::Unconstrained)?;")
        lines.append("    let length_usize = length_integer.try_to_usize()")
        lines.append('        .expect("failed to convert length to usize");')
        lines.append("    let mut buf = Vec::with_capacity(length_usize);")
        lines.append("    for _ in 0..length_usize {")
        lines.append("        let (new_rest, member) = " + rust_deserialize_call(member["element"], parent_type) + ";")
        lines.append("        buf.push(member);")
        lines.append("        rest = new_rest;")
        lines.append("    }")
        lines.append("    (rest, buf)")
        lines.append("}")
        return "\n".join(lines)
    elif type_name == "CHOICE":
        # inline choice -- constructed name
        choice_name = to_pascal_case(parent_type) + to_pascal_case(member["name"])
        return f"{choice_name}::try_from_uper(rest)?"
    else:
        return f"{to_pascal_case(type_name)}::try_from_uper(rest)?"


def rust_serialize_call(member: Union[dict[str, Any], str], parent_type: Optional[str] = None, self_prefix: bool = True, deref: bool = False) -> str:
    if isinstance(member, str):
        member = {"type": member}
    rust_member_name = rust_identifier(to_snake_case(member["name"]))
    self_prefix_text = "self." if self_prefix else ""
    type_name = member["type"]
    if type_name == "INTEGER":
        constraints = member.get("restricted-to", None)
        if constraints is not None:
            (int_min, int_max) = constraints[0]
            constraint_string = f"Constrained {{ min: crate::asn1_uper::Integer::from_short({int_min}), max: crate::asn1_uper::Integer::from_short({int_max}) }}"
        # TODO: semi-constrained?
        else:
            constraint_string = "Unconstrained"
        return f"crate::asn1_uper::encode_integer(uper_buf, &crate::asn1_uper::WholeNumberConstraint::{constraint_string}, &{self_prefix_text}{rust_member_name})?"
    elif type_name == "OCTET STRING":
        size_constraint = string_size_constraint(member)
        return f"crate::asn1_uper::encode_octet_string(uper_buf, &crate::asn1_uper::WholeNumberConstraint::{size_constraint}, &{self_prefix_text}{rust_member_name})?"
    elif type_name == "BOOLEAN":
        star = "*" if deref else ""
        return f"crate::asn1_uper::encode_bool(uper_buf, {star}{self_prefix_text}{rust_member_name})"
    elif type_name == "UTF8String":
        size_constraint = string_size_constraint(member)
        return f"crate::asn1_uper::encode_octet_string(uper_buf, &crate::asn1_uper::WholeNumberConstraint::{size_constraint}, {self_prefix_text}{rust_member_name}.as_bytes())?"
    elif type_name == "IA5String":
        size_constraint = string_size_constraint(member)
        return f"crate::asn1_uper::encode_ia5_string(uper_buf, &crate::asn1_uper::WholeNumberConstraint::{size_constraint}, &{self_prefix_text}{rust_member_name})?"
    elif type_name == "SEQUENCE OF":
        # TODO: handle length constraints
        member_element = dict(member["element"])
        member_element["name"] = "item"
        lines = ["{"]
        lines.append(f"    crate::asn1_uper::encode_length(uper_buf, &crate::asn1_uper::WholeNumberConstraint::Unconstrained, {self_prefix_text}{rust_member_name}.len())?;")
        lines.append(f"    for item in &{self_prefix_text}{rust_member_name} {{")
        lines.append("        " + rust_serialize_call(member_element, parent_type, self_prefix=False) + ";")
        lines.append("    }")
        lines.append("}")
        return "\n".join(lines)
    else:
        # includes CHOICE
        return f"{self_prefix_text}{rust_member_name}.write_uper(uper_buf)?"


def rust_default_value(member: Union[dict[str, Any], str]) -> str:
    if isinstance(member, str):
        member = {"type": member}
    type_name = member["type"]
    if type_name == "INTEGER":
        return f"crate::asn1_uper::Integer::from_short({member['default']})"
    elif type_name in ("UTF8String", "IA5String"):
        return f'"{member["default"]}".to_owned()'
    else:
        # assume it's an enum
        return f"{to_pascal_case(type_name)}::{to_pascal_case(member['default'])}"


def rustify_type(type_name: str, type_def: dict[str, Any]) -> str:
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    env.filters["pascal"] = to_pascal_case
    env.filters["camel"] = to_camel_case
    env.filters["kebab"] = to_kebab_case
    env.filters["snake"] = to_snake_case
    env.filters["rust_type"] = to_rust_type
    env.filters["sequence_is_extensible"] = lambda type_def: None in type_def["members"]
    env.filters["enum_is_extensible"] = lambda type_def: None in type_def["values"]
    env.filters["choice_is_extensible"] = lambda type_def: None in type_def["members"]
    env.filters["count_optional"] = lambda entries: sum(1 for e in entries if e is not None and (e.get("optional", False) or "default" in e))
    env.filters["enum_base_option_count"] = lambda type_def: sum(1 for e in type_def["values"] if e is not None)
    env.filters["choice_base_option_count"] = lambda type_def: sum(1 for e in type_def["members"] if e is not None)
    env.filters["rust_deserialize_call"] = rust_deserialize_call
    env.filters["rust_serialize_call"] = rust_serialize_call
    env.filters["rust_identifier"] = rust_identifier
    env.filters["rust_default_value"] = rust_default_value
    env.filters["repr"] = repr
    env.filters["dict_replacing"] = dict_replacing

    tpl = env.from_string(TEMPLATE)
    return tpl.render(type_name=type_name, type_def=type_def)


def main():
    parser = argparse.ArgumentParser(
        description="Generate Rust data structures and UPER deserialization procedures for an ASN.1 definition."
    )
    parser.add_argument(
        dest="asn1_source",
        metavar="ASN1SOURCE",
        help="Path to the ASN.1 definition file to read.",
    )
    parser.add_argument(
        dest="rust_dest",
        metavar="RUSTDEST",
        type=argparse.FileType("w", encoding="utf-8"),
        help="Path to the Rust source file to generate.",
    )
    args = parser.parse_args()

    asn1_module = asn1tools.parse_files(args.asn1_source)
    asn1_def = next(iter(asn1_module.values()))

    with args.rust_dest:
        args.rust_dest.write("// This file has been generated by asn1_uper_model.py.\n")
        args.rust_dest.write("// Manual changes are likely to disappear without a trace.\n")
        args.rust_dest.write("\n\n")
        args.rust_dest.write("use serde::{Deserialize, Serialize};")
        args.rust_dest.write("\n\n")

        for type_name, type_def in asn1_def["types"].items():
            type_string = rustify_type(type_name, type_def)
            args.rust_dest.write(type_string)
            args.rust_dest.write("\n")


if __name__ == "__main__":
    main()
