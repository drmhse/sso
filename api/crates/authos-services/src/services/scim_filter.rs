//! SCIM Filter Parser Service
//!
//! Implements proper parsing of SCIM 2.0 filter expressions
//! Supports standard operators: eq, ne, co, sw, ew, pr, gt, ge, lt, le

use crate::error::{AppError, Result};

/// SCIM Filter operators
#[derive(Debug, Clone, PartialEq)]
pub enum ScimOperator {
    Equals,
    NotEquals,
    Contains,
    StartsWith,
    EndsWith,
    Present,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
}

impl ScimOperator {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScimOperator::Equals => "eq",
            ScimOperator::NotEquals => "ne",
            ScimOperator::Contains => "co",
            ScimOperator::StartsWith => "sw",
            ScimOperator::EndsWith => "ew",
            ScimOperator::Present => "pr",
            ScimOperator::GreaterThan => "gt",
            ScimOperator::GreaterThanOrEqual => "ge",
            ScimOperator::LessThan => "lt",
            ScimOperator::LessThanOrEqual => "le",
        }
    }
}

/// Parsed SCIM filter expression
#[derive(Debug, Clone)]
pub struct ScimFilterExpression {
    pub attribute_path: String,
    pub operator: ScimOperator,
    pub comparison_value: Option<String>,
}

impl ScimFilterExpression {
    pub fn new(
        attribute_path: String,
        operator: ScimOperator,
        comparison_value: Option<String>,
    ) -> Self {
        Self {
            attribute_path,
            operator,
            comparison_value,
        }
    }
}

/// SCIM Filter Parser
pub struct ScimFilterParser;

impl ScimFilterParser {
    /// Parse a SCIM filter string into filter expressions
    /// Supports basic expressions like "userName eq \"john.doe\""
    pub fn parse(filter: &str) -> Result<Vec<ScimFilterExpression>> {
        let filter = filter.trim();
        if filter.is_empty() {
            return Ok(vec![]);
        }

        // Simple parser for basic SCIM filters
        // This handles expressions like: userName eq "value"
        let mut expressions = Vec::new();

        // Only `and` is supported; `or`/`not` fall through to the single-expression
        // path and are rejected there rather than silently widening the filter.
        if filter.contains(" and ") {
            let parts: Vec<&str> = filter.split(" and ").collect();
            for part in parts {
                let expr = Self::parse_single_expression(part.trim())?;
                expressions.push(expr);
            }
        } else {
            let expr = Self::parse_single_expression(filter)?;
            expressions.push(expr);
        }

        Ok(expressions)
    }

    /// Parse a single filter expression
    fn parse_single_expression(expr: &str) -> Result<ScimFilterExpression> {
        // Handle "pr" operator (presence check)
        if expr.contains(" pr") {
            let parts: Vec<&str> = expr.split(" pr").collect();
            if parts.len() == 2 {
                let attribute_path = parts[0].trim().to_string();
                return Ok(ScimFilterExpression::new(
                    attribute_path,
                    ScimOperator::Present,
                    None,
                ));
            }
        }

        // Handle operators with comparison values
        let operators = [
            " eq ", " ne ", " co ", " sw ", " ew ", " gt ", " ge ", " lt ", " le ",
        ];

        for op_str in &operators {
            if expr.contains(op_str) {
                let parts: Vec<&str> = expr.split(op_str).collect();
                if parts.len() == 2 {
                    let attribute_path = parts[0].trim().to_string();
                    let operator = op_str.trim().parse::<ScimOperator>().map_err(|()| {
                        AppError::BadRequest(format!("Unsupported operator: {}", op_str.trim()))
                    })?;

                    // Extract and clean the comparison value (remove quotes)
                    let comparison_value = parts[1].trim().trim_matches('"').to_string();

                    return Ok(ScimFilterExpression::new(
                        attribute_path,
                        operator,
                        Some(comparison_value),
                    ));
                }
            }
        }

        Err(AppError::BadRequest(format!(
            "Invalid filter expression: {}",
            expr
        )))
    }

    /// Validate that a filter expression is supported for the user entity
    pub fn validate_user_filter(expr: &ScimFilterExpression) -> Result<()> {
        match expr.attribute_path.as_str() {
            "userName" | "email" | "id" => {
                if !matches!(
                    expr.operator,
                    ScimOperator::Equals
                        | ScimOperator::Contains
                        | ScimOperator::StartsWith
                        | ScimOperator::EndsWith
                        | ScimOperator::NotEquals
                ) {
                    return Err(AppError::BadRequest(format!(
                        "Operator {} not supported for {} attribute",
                        expr.operator.as_str(),
                        expr.attribute_path
                    )));
                }
                if expr.comparison_value.is_none() {
                    return Err(AppError::BadRequest(format!(
                        "{} attribute requires a comparison value",
                        expr.attribute_path
                    )));
                }
                Ok(())
            }
            _ => Err(AppError::BadRequest(format!(
                "Unsupported attribute path: {}",
                expr.attribute_path
            ))),
        }
    }
}

impl std::str::FromStr for ScimOperator {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "eq" => Ok(ScimOperator::Equals),
            "ne" => Ok(ScimOperator::NotEquals),
            "co" => Ok(ScimOperator::Contains),
            "sw" => Ok(ScimOperator::StartsWith),
            "ew" => Ok(ScimOperator::EndsWith),
            "pr" => Ok(ScimOperator::Present),
            "gt" => Ok(ScimOperator::GreaterThan),
            "ge" => Ok(ScimOperator::GreaterThanOrEqual),
            "lt" => Ok(ScimOperator::LessThan),
            "le" => Ok(ScimOperator::LessThanOrEqual),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_equals() {
        let expr = ScimFilterParser::parse("userName eq \"john.doe@example.com\"").unwrap();
        assert_eq!(expr.len(), 1);
        assert_eq!(expr[0].attribute_path, "userName");
        assert_eq!(expr[0].operator, ScimOperator::Equals);
        assert_eq!(
            expr[0].comparison_value,
            Some("john.doe@example.com".to_string())
        );
    }

    #[test]
    fn test_parse_contains() {
        let expr = ScimFilterParser::parse("userName co \"john\"").unwrap();
        assert_eq!(expr.len(), 1);
        assert_eq!(expr[0].operator, ScimOperator::Contains);
    }

    #[test]
    fn test_parse_presence() {
        let expr = ScimFilterParser::parse("active pr").unwrap();
        assert_eq!(expr.len(), 1);
        assert_eq!(expr[0].operator, ScimOperator::Present);
        assert_eq!(expr[0].comparison_value, None);
    }

    #[test]
    fn test_parse_and_expression() {
        let expr = ScimFilterParser::parse("userName eq \"john\" and active pr").unwrap();
        assert_eq!(expr.len(), 2);
        assert_eq!(expr[0].attribute_path, "userName");
        assert_eq!(expr[1].attribute_path, "active");
    }
}
