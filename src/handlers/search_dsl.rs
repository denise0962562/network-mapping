use std::net::IpAddr;
use std::str::FromStr;

use chrono::{DateTime, Duration, Utc};
use ipnet::IpNet;
use serde_json::{Value, json};

const MAX_QUERY_LENGTH: usize = 2_048;
const MAX_DEPTH: usize = 12;
const MAX_PREDICATES: usize = 50;
const MAX_IN_VALUES: usize = 100;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Expr {
    Predicate(Predicate),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    HasEndpoint(Box<Expr>),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Predicate {
    field: Field,
    operator: Operator,
    values: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Field {
    Ip,
    Asn,
    Isp,
    Org,
    Country,
    City,
    Tag,
    TagId,
    TagKind,
    Port,
    Protocol,
    Service,
    Banner,
    Title,
    HttpBody,
    TlsSubject,
    Source,
    Scanner,
    FirstSeen,
    LastSeen,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Operator {
    Eq,
    NotEq,
    Contains,
    NotContains,
    Greater,
    GreaterEq,
    Less,
    LessEq,
    In,
    NotIn,
    Colon,
    Exists,
}

#[derive(Clone, Debug, PartialEq)]
enum TokenKind {
    Word(String),
    String(String),
    LeftParen,
    RightParen,
    Comma,
    Eq,
    NotEq,
    Contains,
    NotContains,
    Greater,
    GreaterEq,
    Less,
    LessEq,
}

#[derive(Clone, Debug, PartialEq)]
struct Token {
    kind: TokenKind,
    start: usize,
    end: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SearchSyntaxError {
    pub(crate) message: String,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

impl SearchSyntaxError {
    fn new(message: impl Into<String>, start: usize, end: usize) -> Self {
        Self {
            message: message.into(),
            start,
            end,
        }
    }
}

#[derive(Debug)]
pub(crate) struct CompiledFilter {
    pub(crate) sql: String,
    pub(crate) parameters: Vec<String>,
}

#[derive(Debug)]
pub(crate) enum ElasticsearchCompilation {
    Supported(Value),
    RequiresPostgres,
}

pub(crate) fn parse_and_compile_elasticsearch(
    query: &str,
) -> Result<ElasticsearchCompilation, SearchSyntaxError> {
    let (expression, normalized_query) = parse_expression(query)?;
    let mut compiler = ElasticsearchCompiler::default();
    let Some(filter) = compiler.compile_expr(&expression)? else {
        return Ok(ElasticsearchCompilation::RequiresPostgres);
    };
    if compiler.predicate_count > MAX_PREDICATES {
        return Err(SearchSyntaxError::new(
            format!("查询条件不能超过 {MAX_PREDICATES} 个"),
            0,
            normalized_query.len(),
        ));
    }
    Ok(ElasticsearchCompilation::Supported(filter))
}

#[derive(Default)]
struct ElasticsearchCompiler {
    predicate_count: usize,
}

impl ElasticsearchCompiler {
    fn compile_expr(&mut self, expression: &Expr) -> Result<Option<Value>, SearchSyntaxError> {
        match expression {
            Expr::Predicate(predicate) => {
                self.predicate_count += 1;
                self.compile_predicate(predicate).map(Some)
            }
            Expr::And(left, right) => {
                let (Some(left), Some(right)) =
                    (self.compile_expr(left)?, self.compile_expr(right)?)
                else {
                    return Ok(None);
                };
                Ok(Some(json!({"bool": {"filter": [left, right]}})))
            }
            Expr::Or(left, right) => {
                let (Some(left), Some(right)) =
                    (self.compile_expr(left)?, self.compile_expr(right)?)
                else {
                    return Ok(None);
                };
                Ok(Some(json!({
                    "bool": {"should": [left, right], "minimum_should_match": 1}
                })))
            }
            // SQL 的三值逻辑会让 NOT 对缺失字段的行为不同于 ES must_not。
            // 复杂 NOT 和跨端点条件继续走 PostgreSQL，以保证结果语义完全一致。
            Expr::Not(_) | Expr::HasEndpoint(_) => Ok(None),
        }
    }

    fn compile_predicate(&self, predicate: &Predicate) -> Result<Value, SearchSyntaxError> {
        let operator = if predicate.operator == Operator::Colon {
            predicate.field.default_colon_operator()
        } else {
            predicate.operator
        };
        if operator == Operator::Exists {
            return Ok(json!({"exists": {"field": es_field(predicate.field)}}));
        }
        if predicate.values.is_empty() {
            return Err(SearchSyntaxError::new("搜索值不能为空", 0, 0));
        }
        match predicate.field {
            Field::Ip => self.compile_ip(operator, &predicate.values),
            Field::Port | Field::TagId => {
                self.compile_integer(predicate.field, operator, &predicate.values)
            }
            Field::FirstSeen | Field::LastSeen => {
                self.compile_time(predicate.field, operator, &predicate.values)
            }
            field => self.compile_text(field, operator, &predicate.values),
        }
    }

    fn compile_ip(
        &self,
        operator: Operator,
        values: &[String],
    ) -> Result<Value, SearchSyntaxError> {
        if !matches!(
            operator,
            Operator::Eq | Operator::NotEq | Operator::In | Operator::NotIn
        ) {
            return Err(unsupported_operator(Field::Ip));
        }
        let mut normalized = Vec::with_capacity(values.len());
        for value in values {
            if value.contains('/') {
                normalized.push(normalize_network(value)?);
            } else {
                normalized.push(
                    IpAddr::from_str(value)
                        .map_err(|_| SearchSyntaxError::new("IP 地址格式无效", 0, 0))?
                        .to_string(),
                );
            }
        }
        let positive = if normalized.len() == 1 {
            json!({"term": {"ip": normalized.remove(0)}})
        } else {
            json!({"terms": {"ip": normalized}})
        };
        Ok(negative_filter(operator, "ip", positive, false))
    }

    fn compile_integer(
        &self,
        field: Field,
        operator: Operator,
        values: &[String],
    ) -> Result<Value, SearchSyntaxError> {
        if matches!(operator, Operator::Contains | Operator::NotContains) {
            return Err(unsupported_operator(field));
        }
        let mut parsed_values = Vec::with_capacity(values.len());
        for value in values {
            let parsed = value.parse::<i64>().map_err(|_| {
                SearchSyntaxError::new(format!("{} 必须是数字", field.display_name()), 0, 0)
            })?;
            if field == Field::Port && !(1..=65_535).contains(&parsed) {
                return Err(SearchSyntaxError::new("端口必须在 1 到 65535 之间", 0, 0));
            }
            if field == Field::TagId && parsed <= 0 {
                return Err(SearchSyntaxError::new("tag.id 必须是正整数", 0, 0));
            }
            parsed_values.push(parsed);
        }
        let name = es_field(field);
        if matches!(
            operator,
            Operator::Greater | Operator::GreaterEq | Operator::Less | Operator::LessEq
        ) {
            if parsed_values.len() != 1 {
                return Err(unsupported_operator(field));
            }
            let range_operator = match operator {
                Operator::Greater => "gt",
                Operator::GreaterEq => "gte",
                Operator::Less => "lt",
                Operator::LessEq => "lte",
                _ => unreachable!(),
            };
            return Ok(json!({"range": {(name): {(range_operator): parsed_values[0]}}}));
        }
        let positive = if parsed_values.len() == 1 {
            json!({"term": {(name): parsed_values[0]}})
        } else {
            json!({"terms": {(name): parsed_values}})
        };
        Ok(negative_filter(
            operator,
            name,
            positive,
            field == Field::TagId,
        ))
    }

    fn compile_time(
        &self,
        field: Field,
        operator: Operator,
        values: &[String],
    ) -> Result<Value, SearchSyntaxError> {
        if values.len() != 1
            || !matches!(
                operator,
                Operator::Eq
                    | Operator::NotEq
                    | Operator::Greater
                    | Operator::GreaterEq
                    | Operator::Less
                    | Operator::LessEq
            )
        {
            return Err(unsupported_operator(field));
        }
        let value = normalize_time(&values[0])?;
        let name = es_field(field);
        if matches!(operator, Operator::Eq | Operator::NotEq) {
            let positive = json!({"term": {(name): value}});
            return Ok(negative_filter(operator, name, positive, false));
        }
        let range_operator = match operator {
            Operator::Greater => "gt",
            Operator::GreaterEq => "gte",
            Operator::Less => "lt",
            Operator::LessEq => "lte",
            _ => unreachable!(),
        };
        Ok(json!({"range": {(name): {(range_operator): value}}}))
    }

    fn compile_text(
        &self,
        field: Field,
        operator: Operator,
        values: &[String],
    ) -> Result<Value, SearchSyntaxError> {
        if matches!(
            operator,
            Operator::Greater | Operator::GreaterEq | Operator::Less | Operator::LessEq
        ) {
            return Err(unsupported_operator(field));
        }
        for value in values {
            validate_text_value(field, value)?;
        }
        let name = es_field(field);
        let contains = matches!(operator, Operator::Contains | Operator::NotContains);
        let exact_keyword = matches!(
            field,
            Field::Protocol
                | Field::Service
                | Field::Country
                | Field::Source
                | Field::Tag
                | Field::TagKind
        );
        let normalized_values = values
            .iter()
            .map(|value| {
                let value = if field == Field::Asn {
                    value
                        .strip_prefix("AS")
                        .or_else(|| value.strip_prefix("as"))
                        .unwrap_or(value)
                } else {
                    value
                };
                if exact_keyword && !contains {
                    value.to_lowercase()
                } else {
                    value.to_owned()
                }
            })
            .collect::<Vec<_>>();
        let positive = if contains || !exact_keyword {
            let wildcard_name = es_contains_field(field);
            let clauses = normalized_values
                .iter()
                .map(|value| {
                    let escaped = escape_es_wildcard(value);
                    let pattern = if contains {
                        format!("*{escaped}*")
                    } else {
                        escaped
                    };
                    json!({"wildcard": {(wildcard_name): {"value": pattern, "case_insensitive": true}}})
                })
                .collect::<Vec<_>>();
            if clauses.len() == 1 {
                clauses.into_iter().next().expect("one wildcard clause")
            } else {
                json!({"bool": {"should": clauses, "minimum_should_match": 1}})
            }
        } else if normalized_values.len() == 1 {
            json!({"term": {(name): normalized_values[0]}})
        } else {
            json!({"terms": {(name): normalized_values}})
        };
        let missing_matches_negative = matches!(field, Field::Tag | Field::TagKind);
        Ok(negative_filter(
            operator,
            name,
            positive,
            missing_matches_negative,
        ))
    }
}

fn negative_filter(
    operator: Operator,
    field: &str,
    positive: Value,
    missing_matches: bool,
) -> Value {
    if !matches!(
        operator,
        Operator::NotEq | Operator::NotContains | Operator::NotIn
    ) {
        return positive;
    }
    if missing_matches {
        json!({"bool": {"must_not": [positive]}})
    } else {
        json!({"bool": {"filter": [{"exists": {"field": field}}], "must_not": [positive]}})
    }
}

fn es_field(field: Field) -> &'static str {
    match field {
        Field::Ip => "ip",
        Field::Asn => "asn",
        Field::Isp => "isp",
        Field::Org => "as_org",
        Field::Country => "country_code",
        Field::City => "city_name",
        Field::Tag => "tag_names",
        Field::TagId => "tag_ids",
        Field::TagKind => "tag_kinds",
        Field::Port => "port",
        Field::Protocol => "protocol",
        Field::Service => "service",
        Field::Banner => "banner",
        Field::Title => "title",
        Field::HttpBody => "http_body",
        Field::TlsSubject => "tls_subject",
        Field::Source => "source",
        Field::Scanner => "scanner_name",
        Field::FirstSeen => "first_seen",
        Field::LastSeen => "last_seen",
    }
}

fn es_contains_field(field: Field) -> &'static str {
    match field {
        Field::Title => "title_contains",
        Field::HttpBody => "http_body_contains",
        _ => es_field(field),
    }
}

fn escape_es_wildcard(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('*', "\\*")
        .replace('?', "\\?")
}

impl Field {
    fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "ip" | "network" => Some(Self::Ip),
            "asn" => Some(Self::Asn),
            "isp" => Some(Self::Isp),
            "org" | "as_org" => Some(Self::Org),
            "country" | "country_code" => Some(Self::Country),
            "city" | "city_name" => Some(Self::City),
            "tag" => Some(Self::Tag),
            "tag.id" => Some(Self::TagId),
            "tag.kind" => Some(Self::TagKind),
            "port" => Some(Self::Port),
            "protocol" => Some(Self::Protocol),
            "service" => Some(Self::Service),
            "banner" => Some(Self::Banner),
            "title" | "http.title" => Some(Self::Title),
            "http_body" | "http.body" => Some(Self::HttpBody),
            "tls_subject" | "tls.subject" => Some(Self::TlsSubject),
            "source" => Some(Self::Source),
            "scanner" | "scanner_name" => Some(Self::Scanner),
            "first_seen" => Some(Self::FirstSeen),
            "last_seen" => Some(Self::LastSeen),
            _ => None,
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Asn => "asn",
            Self::Isp => "isp",
            Self::Org => "org",
            Self::Country => "country",
            Self::City => "city",
            Self::Tag => "tag",
            Self::TagId => "tag.id",
            Self::TagKind => "tag.kind",
            Self::Port => "port",
            Self::Protocol => "protocol",
            Self::Service => "service",
            Self::Banner => "banner",
            Self::Title => "title",
            Self::HttpBody => "http_body",
            Self::TlsSubject => "tls_subject",
            Self::Source => "source",
            Self::Scanner => "scanner",
            Self::FirstSeen => "first_seen",
            Self::LastSeen => "last_seen",
        }
    }

    fn is_endpoint(self) -> bool {
        matches!(
            self,
            Self::Port
                | Self::Protocol
                | Self::Service
                | Self::Banner
                | Self::Title
                | Self::HttpBody
                | Self::TlsSubject
                | Self::Source
        )
    }

    fn default_colon_operator(self) -> Operator {
        match self {
            Self::Service
            | Self::Banner
            | Self::Title
            | Self::HttpBody
            | Self::TlsSubject
            | Self::Isp
            | Self::Org
            | Self::City
            | Self::Scanner => Operator::Contains,
            Self::Ip
            | Self::Asn
            | Self::Country
            | Self::Tag
            | Self::TagId
            | Self::TagKind
            | Self::Port
            | Self::Protocol
            | Self::Source
            | Self::FirstSeen
            | Self::LastSeen => Operator::Eq,
        }
    }
}

pub(crate) fn parse_and_compile(query: &str) -> Result<CompiledFilter, SearchSyntaxError> {
    let (expression, query) = parse_expression(query)?;
    let mut compiler = Compiler::default();
    let sql = compiler.compile_expr(&expression, "result", false)?;
    if compiler.predicate_count > MAX_PREDICATES {
        return Err(SearchSyntaxError::new(
            format!("查询条件不能超过 {MAX_PREDICATES} 个"),
            0,
            query.len(),
        ));
    }
    Ok(CompiledFilter {
        sql,
        parameters: compiler.parameters,
    })
}

fn parse_expression(query: &str) -> Result<(Expr, &str), SearchSyntaxError> {
    let query = query.trim();
    if query.is_empty() {
        return Err(SearchSyntaxError::new("请输入搜索内容", 0, 0));
    }
    if query.chars().count() > MAX_QUERY_LENGTH {
        return Err(SearchSyntaxError::new(
            format!("查询内容不能超过 {MAX_QUERY_LENGTH} 个字符"),
            0,
            query.len(),
        ));
    }

    let expression = if let Ok(ip) = IpAddr::from_str(query) {
        Expr::Predicate(Predicate {
            field: Field::Ip,
            operator: Operator::Eq,
            values: vec![ip.to_string()],
        })
    } else if query.contains('/') {
        match normalize_network(query) {
            Ok(network) => Expr::Predicate(Predicate {
                field: Field::Ip,
                operator: Operator::In,
                values: vec![network],
            }),
            Err(_) => Parser::new(tokenize(query)?).parse()?,
        }
    } else {
        Parser::new(tokenize(query)?).parse()?
    };

    Ok((expression, query))
}

fn tokenize(input: &str) -> Result<Vec<Token>, SearchSyntaxError> {
    let mut tokens = Vec::new();
    let mut iter = input.char_indices().peekable();
    while let Some((start, ch)) = iter.next() {
        if ch.is_whitespace() {
            continue;
        }
        let single = |kind, end| Token { kind, start, end };
        match ch {
            '(' => tokens.push(single(TokenKind::LeftParen, start + 1)),
            ')' => tokens.push(single(TokenKind::RightParen, start + 1)),
            ',' => tokens.push(single(TokenKind::Comma, start + 1)),
            '=' => tokens.push(single(TokenKind::Eq, start + 1)),
            '!' => {
                let Some((next_index, next)) = iter.next() else {
                    return Err(SearchSyntaxError::new(
                        "! 后必须是 = 或 ~",
                        start,
                        start + 1,
                    ));
                };
                let kind = match next {
                    '=' => TokenKind::NotEq,
                    '~' => TokenKind::NotContains,
                    _ => {
                        return Err(SearchSyntaxError::new(
                            "! 后必须是 = 或 ~",
                            start,
                            next_index + next.len_utf8(),
                        ));
                    }
                };
                tokens.push(single(kind, next_index + next.len_utf8()));
            }
            '~' => tokens.push(single(TokenKind::Contains, start + 1)),
            '>' | '<' => {
                let mut end = start + 1;
                let has_equal = iter.peek().is_some_and(|(_, value)| *value == '=');
                if has_equal && let Some((index, value)) = iter.next() {
                    end = index + value.len_utf8();
                }
                let kind = match (ch, has_equal) {
                    ('>', true) => TokenKind::GreaterEq,
                    ('>', false) => TokenKind::Greater,
                    ('<', true) => TokenKind::LessEq,
                    ('<', false) => TokenKind::Less,
                    _ => unreachable!(),
                };
                tokens.push(single(kind, end));
            }
            '\'' | '"' => {
                let quote = ch;
                let mut value = String::new();
                let mut end = None;
                while let Some((index, current)) = iter.next() {
                    if current == quote {
                        end = Some(index + current.len_utf8());
                        break;
                    }
                    if current == '\\' {
                        let Some((_, escaped)) = iter.next() else {
                            return Err(SearchSyntaxError::new(
                                "字符串末尾不能是转义符",
                                start,
                                input.len(),
                            ));
                        };
                        value.push(escaped);
                    } else {
                        value.push(current);
                    }
                }
                let Some(end) = end else {
                    return Err(SearchSyntaxError::new(
                        "字符串缺少结束引号",
                        start,
                        input.len(),
                    ));
                };
                tokens.push(Token {
                    kind: TokenKind::String(value),
                    start,
                    end,
                });
            }
            _ => {
                let mut end = start + ch.len_utf8();
                while let Some((index, next)) = iter.peek().copied() {
                    if next.is_whitespace()
                        || matches!(
                            next,
                            '(' | ')' | ',' | '=' | '!' | '~' | '>' | '<' | '\'' | '"'
                        )
                    {
                        break;
                    }
                    iter.next();
                    end = index + next.len_utf8();
                }
                tokens.push(Token {
                    kind: TokenKind::Word(input[start..end].to_owned()),
                    start,
                    end,
                });
            }
        }
    }
    Ok(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    position: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            position: 0,
        }
    }

    fn parse(mut self) -> Result<Expr, SearchSyntaxError> {
        if self.tokens.is_empty() {
            return Err(SearchSyntaxError::new("请输入搜索内容", 0, 0));
        }
        let expression = self.parse_or(0)?;
        if let Some(token) = self.peek() {
            return Err(SearchSyntaxError::new(
                "条件之间需要使用 AND 或 OR",
                token.start,
                token.end,
            ));
        }
        Ok(expression)
    }

    fn parse_or(&mut self, depth: usize) -> Result<Expr, SearchSyntaxError> {
        self.ensure_depth(depth)?;
        let mut expression = self.parse_and(depth)?;
        while self.consume_keyword("OR") {
            let right = self.parse_and(depth)?;
            expression = Expr::Or(Box::new(expression), Box::new(right));
        }
        Ok(expression)
    }

    fn parse_and(&mut self, depth: usize) -> Result<Expr, SearchSyntaxError> {
        self.ensure_depth(depth)?;
        let mut expression = self.parse_unary(depth)?;
        while self.consume_keyword("AND") {
            let right = self.parse_unary(depth)?;
            expression = Expr::And(Box::new(expression), Box::new(right));
        }
        Ok(expression)
    }

    fn parse_unary(&mut self, depth: usize) -> Result<Expr, SearchSyntaxError> {
        self.ensure_depth(depth)?;
        if self.consume_keyword("NOT") {
            return Ok(Expr::Not(Box::new(self.parse_unary(depth + 1)?)));
        }
        self.parse_primary(depth)
    }

    fn parse_primary(&mut self, depth: usize) -> Result<Expr, SearchSyntaxError> {
        self.ensure_depth(depth)?;
        if self.consume_kind(&TokenKind::LeftParen) {
            let expression = self.parse_or(depth + 1)?;
            self.expect_kind(&TokenKind::RightParen, "缺少右括号 )")?;
            return Ok(expression);
        }
        if self.consume_keyword("EXISTS") {
            self.expect_kind(&TokenKind::LeftParen, "EXISTS 后需要左括号 (")?;
            let (field_name, token) = self.expect_word("EXISTS 中需要字段名")?;
            let field = Field::parse(&field_name).ok_or_else(|| {
                SearchSyntaxError::new(format!("不支持字段 {field_name}"), token.start, token.end)
            })?;
            self.expect_kind(&TokenKind::RightParen, "EXISTS 缺少右括号 )")?;
            return Ok(Expr::Predicate(Predicate {
                field,
                operator: Operator::Exists,
                values: Vec::new(),
            }));
        }
        if self.consume_keyword("HAS_ENDPOINT") {
            self.expect_kind(&TokenKind::LeftParen, "has_endpoint 后需要左括号 (")?;
            let expression = self.parse_or(depth + 1)?;
            self.expect_kind(&TokenKind::RightParen, "has_endpoint 缺少右括号 )")?;
            return Ok(Expr::HasEndpoint(Box::new(expression)));
        }
        self.parse_predicate()
    }

    fn parse_predicate(&mut self) -> Result<Expr, SearchSyntaxError> {
        let (first, first_token) = self.expect_word("这里需要字段名")?;
        if let Some((field_name, shorthand_value)) = first.split_once(':')
            && let Some(field) = Field::parse(field_name)
        {
            let value = if shorthand_value.is_empty() {
                self.expect_value("冒号后需要搜索值")?
            } else {
                shorthand_value.to_owned()
            };
            return Ok(Expr::Predicate(Predicate {
                field,
                operator: Operator::Colon,
                values: vec![value],
            }));
        }

        let field = Field::parse(&first).ok_or_else(|| {
            SearchSyntaxError::new(
                format!("不支持字段 {first}"),
                first_token.start,
                first_token.end,
            )
        })?;
        let operator = self.parse_operator()?;
        let values = if operator == Operator::Exists {
            Vec::new()
        } else if matches!(operator, Operator::In | Operator::NotIn) {
            self.parse_in_values()?
        } else {
            vec![self.expect_value("操作符后需要搜索值")?]
        };
        Ok(Expr::Predicate(Predicate {
            field,
            operator,
            values,
        }))
    }

    fn parse_operator(&mut self) -> Result<Operator, SearchSyntaxError> {
        let Some(token) = self.next().cloned() else {
            let end = self.tokens.last().map(|value| value.end).unwrap_or(0);
            return Err(SearchSyntaxError::new("字段后缺少操作符", end, end));
        };
        let operator = match &token.kind {
            TokenKind::Eq => Operator::Eq,
            TokenKind::NotEq => Operator::NotEq,
            TokenKind::Contains => Operator::Contains,
            TokenKind::NotContains => Operator::NotContains,
            TokenKind::Greater => Operator::Greater,
            TokenKind::GreaterEq => Operator::GreaterEq,
            TokenKind::Less => Operator::Less,
            TokenKind::LessEq => Operator::LessEq,
            TokenKind::Word(value) if value.eq_ignore_ascii_case("IN") => Operator::In,
            TokenKind::Word(value) if value.eq_ignore_ascii_case("EXISTS") => Operator::Exists,
            TokenKind::Word(value) if value.eq_ignore_ascii_case("NOT") => {
                if self.consume_keyword("IN") {
                    Operator::NotIn
                } else {
                    return Err(SearchSyntaxError::new(
                        "字段后的 NOT 只能用于 NOT IN",
                        token.start,
                        token.end,
                    ));
                }
            }
            _ => {
                return Err(SearchSyntaxError::new(
                    "不支持的操作符",
                    token.start,
                    token.end,
                ));
            }
        };
        Ok(operator)
    }

    fn parse_in_values(&mut self) -> Result<Vec<String>, SearchSyntaxError> {
        if !self.consume_kind(&TokenKind::LeftParen) {
            return Ok(vec![self.expect_value("IN 后需要值或值列表")?]);
        }
        let mut values = Vec::new();
        loop {
            if self.consume_kind(&TokenKind::RightParen) {
                if values.is_empty() {
                    let end = self
                        .tokens
                        .get(self.position.saturating_sub(1))
                        .map(|v| v.end)
                        .unwrap_or(0);
                    return Err(SearchSyntaxError::new(
                        "IN 列表不能为空",
                        end.saturating_sub(1),
                        end,
                    ));
                }
                break;
            }
            values.push(self.expect_value("IN 列表中需要值")?);
            if self.consume_kind(&TokenKind::Comma) {
                continue;
            }
            self.expect_kind(&TokenKind::RightParen, "IN 列表缺少右括号 )")?;
            break;
        }
        if values.len() > MAX_IN_VALUES {
            return Err(SearchSyntaxError::new(
                format!("IN 列表最多包含 {MAX_IN_VALUES} 个值"),
                0,
                0,
            ));
        }
        Ok(values)
    }

    fn expect_value(&mut self, message: &str) -> Result<String, SearchSyntaxError> {
        let Some(token) = self.next() else {
            let end = self.tokens.last().map(|value| value.end).unwrap_or(0);
            return Err(SearchSyntaxError::new(message, end, end));
        };
        match &token.kind {
            TokenKind::Word(value) | TokenKind::String(value) => Ok(value.clone()),
            _ => Err(SearchSyntaxError::new(message, token.start, token.end)),
        }
    }

    fn expect_word(&mut self, message: &str) -> Result<(String, Token), SearchSyntaxError> {
        let Some(token) = self.next().cloned() else {
            let end = self.tokens.last().map(|value| value.end).unwrap_or(0);
            return Err(SearchSyntaxError::new(message, end, end));
        };
        match &token.kind {
            TokenKind::Word(value) => Ok((value.clone(), token)),
            _ => Err(SearchSyntaxError::new(message, token.start, token.end)),
        }
    }

    fn ensure_depth(&self, depth: usize) -> Result<(), SearchSyntaxError> {
        if depth <= MAX_DEPTH {
            return Ok(());
        }
        let token = self.peek();
        Err(SearchSyntaxError::new(
            format!("查询嵌套不能超过 {MAX_DEPTH} 层"),
            token.map(|value| value.start).unwrap_or(0),
            token.map(|value| value.end).unwrap_or(0),
        ))
    }

    fn consume_keyword(&mut self, keyword: &str) -> bool {
        let matches = self.peek().is_some_and(|token| {
            matches!(&token.kind, TokenKind::Word(value) if value.eq_ignore_ascii_case(keyword))
        });
        if matches {
            self.position += 1;
        }
        matches
    }

    fn consume_kind(&mut self, kind: &TokenKind) -> bool {
        let matches = self.peek().is_some_and(|token| &token.kind == kind);
        if matches {
            self.position += 1;
        }
        matches
    }

    fn expect_kind(&mut self, kind: &TokenKind, message: &str) -> Result<(), SearchSyntaxError> {
        if self.consume_kind(kind) {
            return Ok(());
        }
        let token = self.peek();
        Err(SearchSyntaxError::new(
            message,
            token
                .map(|value| value.start)
                .unwrap_or_else(|| self.tokens.last().map(|value| value.end).unwrap_or(0)),
            token
                .map(|value| value.end)
                .unwrap_or_else(|| self.tokens.last().map(|value| value.end).unwrap_or(0)),
        ))
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }

    fn next(&mut self) -> Option<&Token> {
        let token = self.tokens.get(self.position);
        if token.is_some() {
            self.position += 1;
        }
        token
    }
}

#[derive(Default)]
struct Compiler {
    parameters: Vec<String>,
    predicate_count: usize,
}

impl Compiler {
    fn compile_expr(
        &mut self,
        expression: &Expr,
        alias: &str,
        endpoint_scope: bool,
    ) -> Result<String, SearchSyntaxError> {
        match expression {
            Expr::Predicate(predicate) => {
                if endpoint_scope && !predicate.field.is_endpoint() {
                    return Err(SearchSyntaxError::new(
                        format!(
                            "has_endpoint 中不能使用资产字段 {}",
                            predicate.field.display_name()
                        ),
                        0,
                        0,
                    ));
                }
                self.predicate_count += 1;
                self.compile_predicate(predicate, alias)
            }
            Expr::And(left, right) => Ok(format!(
                "({} AND {})",
                self.compile_expr(left, alias, endpoint_scope)?,
                self.compile_expr(right, alias, endpoint_scope)?
            )),
            Expr::Or(left, right) => Ok(format!(
                "({} OR {})",
                self.compile_expr(left, alias, endpoint_scope)?,
                self.compile_expr(right, alias, endpoint_scope)?
            )),
            Expr::Not(inner) => Ok(format!(
                "(NOT {})",
                self.compile_expr(inner, alias, endpoint_scope)?
            )),
            Expr::HasEndpoint(inner) => {
                if endpoint_scope {
                    return Err(SearchSyntaxError::new("has_endpoint 不能嵌套", 0, 0));
                }
                let predicate = self.compile_expr(inner, "candidate", true)?;
                Ok(format!(
                    "EXISTS (SELECT 1 FROM search_rows candidate WHERE candidate.ip_address = {alias}.ip_address AND {predicate})"
                ))
            }
        }
    }

    fn compile_predicate(
        &mut self,
        predicate: &Predicate,
        alias: &str,
    ) -> Result<String, SearchSyntaxError> {
        let operator = if predicate.operator == Operator::Colon {
            predicate.field.default_colon_operator()
        } else {
            predicate.operator
        };
        if operator == Operator::Exists {
            return self.compile_exists(predicate.field, alias);
        }
        if predicate.values.is_empty() {
            return Err(SearchSyntaxError::new("搜索值不能为空", 0, 0));
        }
        match predicate.field {
            Field::Ip => self.compile_ip(operator, &predicate.values, alias),
            Field::Port | Field::TagId => {
                self.compile_integer(predicate.field, operator, &predicate.values, alias)
            }
            Field::FirstSeen | Field::LastSeen => {
                self.compile_time(predicate.field, operator, &predicate.values, alias)
            }
            Field::Tag | Field::TagKind => {
                self.compile_tag(predicate.field, operator, &predicate.values, alias)
            }
            Field::Asn
            | Field::Isp
            | Field::Org
            | Field::Country
            | Field::City
            | Field::Protocol
            | Field::Service
            | Field::Banner
            | Field::Title
            | Field::HttpBody
            | Field::TlsSubject
            | Field::Source
            | Field::Scanner => {
                self.compile_text(predicate.field, operator, &predicate.values, alias)
            }
        }
    }

    fn compile_exists(&self, field: Field, alias: &str) -> Result<String, SearchSyntaxError> {
        let sql = match field {
            Field::Ip => "TRUE".to_owned(),
            Field::Port => format!("{alias}.port > 0"),
            Field::Tag | Field::TagId | Field::TagKind => format!(
                "EXISTS (SELECT 1 FROM asset_ip_tag assignment JOIN asset_tag tag ON tag.id = assignment.tag_id WHERE assignment.ip_address = {alias}.ip_address AND tag.is_active)"
            ),
            Field::FirstSeen => format!("{alias}.first_seen_at IS NOT NULL"),
            Field::LastSeen => format!("{alias}.last_seen_at IS NOT NULL"),
            field => format!(
                "NULLIF(BTRIM({}), '') IS NOT NULL",
                text_column(field, alias).ok_or_else(|| {
                    SearchSyntaxError::new(
                        format!("字段 {} 不支持 EXISTS", field.display_name()),
                        0,
                        0,
                    )
                })?
            ),
        };
        Ok(sql)
    }

    fn compile_ip(
        &mut self,
        operator: Operator,
        values: &[String],
        alias: &str,
    ) -> Result<String, SearchSyntaxError> {
        if matches!(
            operator,
            Operator::Contains
                | Operator::NotContains
                | Operator::Greater
                | Operator::GreaterEq
                | Operator::Less
                | Operator::LessEq
        ) {
            return Err(unsupported_operator(Field::Ip));
        }
        let mut clauses = Vec::new();
        for value in values {
            if value.contains('/') {
                let network = normalize_network(value)?;
                let parameter = self.push_parameter(network);
                clauses.push(format!("{alias}.ip_address <<= {parameter}::TEXT::INET"));
            } else {
                let ip = IpAddr::from_str(value)
                    .map_err(|_| SearchSyntaxError::new("IP 地址格式无效", 0, 0))?;
                let parameter = self.push_parameter(ip.to_string());
                clauses.push(format!("{alias}.ip_address = {parameter}::TEXT::INET"));
            }
        }
        let joined = join_exact_clauses(operator, clauses)?;
        Ok(joined)
    }

    fn compile_integer(
        &mut self,
        field: Field,
        operator: Operator,
        values: &[String],
        alias: &str,
    ) -> Result<String, SearchSyntaxError> {
        if matches!(operator, Operator::Contains | Operator::NotContains) {
            return Err(unsupported_operator(field));
        }
        if !matches!(operator, Operator::In | Operator::NotIn) && values.len() != 1 {
            return Err(unsupported_operator(field));
        }
        let column = if field == Field::Port {
            format!("{alias}.port")
        } else {
            "tag.id".to_owned()
        };
        let mut clauses = Vec::new();
        for value in values {
            let parsed = value.parse::<i64>().map_err(|_| {
                SearchSyntaxError::new(format!("{} 必须是数字", field.display_name()), 0, 0)
            })?;
            if field == Field::Port && !(1..=65_535).contains(&parsed) {
                return Err(SearchSyntaxError::new("端口必须在 1 到 65535 之间", 0, 0));
            }
            if field == Field::TagId && parsed <= 0 {
                return Err(SearchSyntaxError::new("tag.id 必须是正整数", 0, 0));
            }
            let parameter = self.push_parameter(parsed.to_string());
            clauses.push(format!("{column} = {parameter}::TEXT::BIGINT"));
        }
        if field == Field::TagId {
            return self.wrap_tag_exists(operator, clauses, alias);
        }
        if matches!(
            operator,
            Operator::Greater
                | Operator::GreaterEq
                | Operator::Less
                | Operator::LessEq
                | Operator::Eq
                | Operator::NotEq
        ) {
            let parameter = clauses.into_iter().next().expect("one clause");
            let eq_fragment = parameter
                .split_once(" = ")
                .map(|(_, value)| value)
                .expect("integer equality fragment");
            let symbol = sql_operator(operator)?;
            return Ok(format!("{column} {symbol} {eq_fragment}"));
        }
        join_exact_clauses(operator, clauses)
    }

    fn compile_time(
        &mut self,
        field: Field,
        operator: Operator,
        values: &[String],
        alias: &str,
    ) -> Result<String, SearchSyntaxError> {
        if values.len() != 1
            || !matches!(
                operator,
                Operator::Eq
                    | Operator::NotEq
                    | Operator::Greater
                    | Operator::GreaterEq
                    | Operator::Less
                    | Operator::LessEq
            )
        {
            return Err(unsupported_operator(field));
        }
        let normalized = normalize_time(&values[0])?;
        let parameter = self.push_parameter(normalized);
        let column = if field == Field::FirstSeen {
            format!("{alias}.first_seen_at")
        } else {
            format!("{alias}.last_seen_at")
        };
        Ok(format!(
            "{column} {} {parameter}::TEXT::TIMESTAMPTZ",
            sql_operator(operator)?
        ))
    }

    fn compile_tag(
        &mut self,
        field: Field,
        operator: Operator,
        values: &[String],
        alias: &str,
    ) -> Result<String, SearchSyntaxError> {
        if matches!(
            operator,
            Operator::Greater | Operator::GreaterEq | Operator::Less | Operator::LessEq
        ) {
            return Err(unsupported_operator(field));
        }
        let column = if field == Field::Tag {
            "tag.name"
        } else {
            "tag.kind"
        };
        let mut clauses = Vec::new();
        for value in values {
            validate_text_value(field, value)?;
            let parameter = self.push_parameter(
                if matches!(operator, Operator::Contains | Operator::NotContains) {
                    escape_like(value)
                } else {
                    value.to_owned()
                },
            );
            let clause = if matches!(operator, Operator::Contains | Operator::NotContains) {
                format!("{column} ILIKE '%' || {parameter} || '%' ESCAPE E'\\\\'")
            } else {
                format!("LOWER({column}) = LOWER({parameter})")
            };
            clauses.push(clause);
        }
        self.wrap_tag_exists(operator, clauses, alias)
    }

    fn wrap_tag_exists(
        &self,
        operator: Operator,
        clauses: Vec<String>,
        alias: &str,
    ) -> Result<String, SearchSyntaxError> {
        let negative = matches!(
            operator,
            Operator::NotEq | Operator::NotContains | Operator::NotIn
        );
        if !matches!(
            operator,
            Operator::Eq
                | Operator::NotEq
                | Operator::Contains
                | Operator::NotContains
                | Operator::In
                | Operator::NotIn
        ) {
            return Err(SearchSyntaxError::new("标签不支持该操作符", 0, 0));
        }
        let condition = clauses.join(" OR ");
        Ok(format!(
            "{}EXISTS (SELECT 1 FROM asset_ip_tag assignment JOIN asset_tag tag ON tag.id = assignment.tag_id WHERE assignment.ip_address = {alias}.ip_address AND tag.is_active AND ({condition}))",
            if negative { "NOT " } else { "" }
        ))
    }

    fn compile_text(
        &mut self,
        field: Field,
        operator: Operator,
        values: &[String],
        alias: &str,
    ) -> Result<String, SearchSyntaxError> {
        if matches!(
            operator,
            Operator::Greater | Operator::GreaterEq | Operator::Less | Operator::LessEq
        ) {
            return Err(unsupported_operator(field));
        }
        let column = text_column(field, alias).ok_or_else(|| unsupported_operator(field))?;
        let mut clauses = Vec::new();
        for raw_value in values {
            validate_text_value(field, raw_value)?;
            let value = if field == Field::Asn {
                raw_value
                    .strip_prefix("AS")
                    .or_else(|| raw_value.strip_prefix("as"))
                    .unwrap_or(raw_value)
                    .to_owned()
            } else if matches!(operator, Operator::Contains | Operator::NotContains) {
                escape_like(raw_value)
            } else {
                raw_value.to_owned()
            };
            let parameter = self.push_parameter(value);
            let clause = if matches!(operator, Operator::Contains | Operator::NotContains) {
                format!("{column} ILIKE '%' || {parameter} || '%' ESCAPE E'\\\\'")
            } else if field == Field::Asn {
                format!(
                    "REGEXP_REPLACE(UPPER(COALESCE({column}, '')), '^AS', '') = REGEXP_REPLACE(UPPER({parameter}), '^AS', '')"
                )
            } else {
                format!("LOWER({column}) = LOWER({parameter})")
            };
            clauses.push(clause);
        }
        if matches!(operator, Operator::Eq | Operator::Contains) && values.len() == 1 {
            return Ok(clauses.remove(0));
        }
        if matches!(operator, Operator::NotEq | Operator::NotContains) && values.len() == 1 {
            return Ok(format!("NOT ({})", clauses.remove(0)));
        }
        join_exact_clauses(operator, clauses)
    }

    fn push_parameter(&mut self, value: String) -> String {
        self.parameters.push(value);
        format!("${}", self.parameters.len() + 2)
    }
}

fn text_column(field: Field, alias: &str) -> Option<String> {
    let name = match field {
        Field::Asn => "asn",
        Field::Isp => "isp",
        Field::Org => "as_org",
        Field::Country => "country_code",
        Field::City => "city_name",
        Field::Protocol => "protocol",
        Field::Service => "service",
        Field::Banner => "banner",
        Field::Title => "title",
        Field::HttpBody => "http_body",
        Field::TlsSubject => "tls_subject",
        Field::Source => "source",
        Field::Scanner => "scanner_name",
        _ => return None,
    };
    Some(format!("{alias}.{name}"))
}

fn join_exact_clauses(
    operator: Operator,
    clauses: Vec<String>,
) -> Result<String, SearchSyntaxError> {
    match operator {
        Operator::Eq | Operator::Contains | Operator::In => {
            Ok(format!("({})", clauses.join(" OR ")))
        }
        Operator::NotEq | Operator::NotContains | Operator::NotIn => {
            Ok(format!("NOT ({})", clauses.join(" OR ")))
        }
        _ => Err(SearchSyntaxError::new("字段不支持该操作符", 0, 0)),
    }
}

fn sql_operator(operator: Operator) -> Result<&'static str, SearchSyntaxError> {
    match operator {
        Operator::Eq => Ok("="),
        Operator::NotEq => Ok("<>"),
        Operator::Greater => Ok(">"),
        Operator::GreaterEq => Ok(">="),
        Operator::Less => Ok("<"),
        Operator::LessEq => Ok("<="),
        _ => Err(SearchSyntaxError::new("字段不支持该操作符", 0, 0)),
    }
}

fn normalize_network(value: &str) -> Result<String, SearchSyntaxError> {
    let Some((ip, prefix)) = value.split_once('/') else {
        return Err(SearchSyntaxError::new("CIDR 必须包含前缀长度", 0, 0));
    };
    let ip = IpAddr::from_str(ip)
        .map_err(|_| SearchSyntaxError::new("CIDR 中的 IP 地址格式无效", 0, 0))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| SearchSyntaxError::new("CIDR 前缀长度格式无效", 0, 0))?;
    let network = IpNet::new(ip, prefix)
        .map_err(|_| SearchSyntaxError::new("CIDR 前缀长度超出范围", 0, 0))?;
    Ok(network.trunc().to_string())
}

fn normalize_time(value: &str) -> Result<String, SearchSyntaxError> {
    if let Some(relative) = value.strip_prefix("now-") {
        if relative.len() < 2 {
            return Err(SearchSyntaxError::new(
                "相对时间格式无效，例如 now-7d",
                0,
                0,
            ));
        }
        let (amount, unit) = relative.split_at(relative.len() - 1);
        let amount = amount
            .parse::<i64>()
            .map_err(|_| SearchSyntaxError::new("相对时间格式无效，例如 now-7d", 0, 0))?;
        if amount <= 0 {
            return Err(SearchSyntaxError::new("相对时间必须大于 0", 0, 0));
        }
        let duration = match unit {
            "m" => Duration::try_minutes(amount),
            "h" => Duration::try_hours(amount),
            "d" => Duration::try_days(amount),
            "w" => Duration::try_weeks(amount),
            _ => {
                return Err(SearchSyntaxError::new(
                    "相对时间单位只支持 m、h、d、w",
                    0,
                    0,
                ));
            }
        }
        .ok_or_else(|| SearchSyntaxError::new("相对时间超出允许范围", 0, 0))?;
        return Utc::now()
            .checked_sub_signed(duration)
            .map(|time| time.to_rfc3339())
            .ok_or_else(|| SearchSyntaxError::new("相对时间超出允许范围", 0, 0));
    }
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.to_rfc3339())
        .map_err(|_| SearchSyntaxError::new("时间必须是 RFC 3339 或 now-7d 格式", 0, 0))
}

fn validate_text_value(field: Field, value: &str) -> Result<(), SearchSyntaxError> {
    let length = value.chars().count();
    let minimum = if matches!(
        field,
        Field::Banner | Field::Title | Field::HttpBody | Field::TlsSubject
    ) {
        2
    } else {
        1
    };
    if !(minimum..=128).contains(&length) {
        return Err(SearchSyntaxError::new(
            format!(
                "{} 的长度必须在 {minimum} 到 128 个字符之间",
                field.display_name()
            ),
            0,
            0,
        ));
    }
    if field == Field::TagKind && !matches!(value, "info" | "malicious" | "benign") {
        return Err(SearchSyntaxError::new(
            "tag.kind 只支持 info、malicious、benign",
            0,
            0,
        ));
    }
    if field == Field::Country && value.chars().count() != 2 {
        return Err(SearchSyntaxError::new("country 必须是两位国家代码", 0, 0));
    }
    Ok(())
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn unsupported_operator(field: Field) -> SearchSyntaxError {
    SearchSyntaxError::new(
        format!("字段 {} 不支持该操作符", field.display_name()),
        0,
        0,
    )
}

#[cfg(test)]
mod tests {
    use super::{ElasticsearchCompilation, parse_and_compile, parse_and_compile_elasticsearch};

    #[test]
    fn compiles_boolean_precedence_and_bound_values() {
        let compiled = parse_and_compile("country = CN OR port = 443 AND service = \"https\"")
            .expect("query should compile");

        assert!(compiled.sql.contains(" OR ("));
        assert!(compiled.sql.contains("result.port = $4::TEXT::BIGINT"));
        assert_eq!(compiled.parameters, vec!["CN", "443", "https"]);
    }

    #[test]
    fn supports_legacy_syntax_and_ipv6() {
        let service = parse_and_compile("service:https").expect("legacy service query");
        assert!(service.sql.contains("ILIKE"));
        assert_eq!(service.parameters, vec!["https"]);

        let ipv6 = parse_and_compile("2001:db8::1").expect("bare ipv6 query");
        assert!(ipv6.sql.contains("result.ip_address = $3::TEXT::INET"));
        assert_eq!(ipv6.parameters, vec!["2001:db8::1"]);
    }

    #[test]
    fn normalizes_cidr_and_compiles_tag_existence() {
        let compiled = parse_and_compile("ip IN 192.168.1.123/24 AND tag = \"生产环境\"")
            .expect("network and tag query");
        assert_eq!(compiled.parameters[0], "192.168.1.0/24");
        assert!(compiled.sql.contains("asset_ip_tag"));
    }

    #[test]
    fn compiles_asset_level_endpoint_requirements() {
        let compiled = parse_and_compile("has_endpoint(port = 80) AND has_endpoint(port = 443)")
            .expect("endpoint requirements");
        assert_eq!(
            compiled.sql.matches("FROM search_rows candidate").count(),
            2
        );
    }

    #[test]
    fn rejects_asset_fields_inside_endpoint_scope() {
        let error = parse_and_compile("has_endpoint(tag = prod)")
            .expect_err("asset field must be rejected");
        assert!(error.message.contains("不能使用资产字段"));
    }

    #[test]
    fn reports_missing_boolean_operator() {
        let error = parse_and_compile("port = 80 service = http")
            .expect_err("implicit boolean operator must be rejected");
        assert_eq!(error.message, "条件之间需要使用 AND 或 OR");
        assert!(error.start > 0);
    }

    #[test]
    fn accepts_many_flat_conditions_within_predicate_limit() {
        let query = (1..=20)
            .map(|port| format!("port != {port}"))
            .collect::<Vec<_>>()
            .join(" AND ");
        parse_and_compile(&query).expect("flat conditions are not nested expressions");
    }

    #[test]
    fn negative_tag_means_not_exists() {
        let compiled = parse_and_compile("tag != retired").expect("negative tag query");
        assert!(compiled.sql.contains("NOT EXISTS"));
    }

    #[test]
    fn rejects_overflowing_relative_time_without_panicking() {
        let error = parse_and_compile("last_seen >= now-9223372036854775807w")
            .expect_err("overflowing relative time must be rejected");
        assert_eq!(error.message, "相对时间超出允许范围");
    }

    #[test]
    fn keeps_search_values_out_of_generated_sql() {
        let compiled = parse_and_compile("service = \"https' OR TRUE --\"")
            .expect("hostile-looking text remains a bound value");
        assert!(!compiled.sql.contains("OR TRUE"));
        assert_eq!(compiled.parameters, vec!["https' OR TRUE --"]);
    }

    #[test]
    fn compiles_supported_queries_to_elasticsearch_filter_dsl() {
        let ElasticsearchCompilation::Supported(filter) = parse_and_compile_elasticsearch(
            "country = CN AND port = 443 AND banner ~ \"Hikvision\"",
        )
        .expect("Elasticsearch filter should compile") else {
            panic!("query should be supported by Elasticsearch");
        };
        let serialized = filter.to_string();
        assert!(serialized.contains("country_code"));
        assert!(serialized.contains("banner"));
        assert!(serialized.contains("*Hikvision*"));
    }

    #[test]
    fn routes_cross_endpoint_and_complex_not_queries_to_postgres() {
        assert!(matches!(
            parse_and_compile_elasticsearch("has_endpoint(port = 443)").unwrap(),
            ElasticsearchCompilation::RequiresPostgres
        ));
        assert!(matches!(
            parse_and_compile_elasticsearch("NOT EXISTS(banner)").unwrap(),
            ElasticsearchCompilation::RequiresPostgres
        ));
    }

    #[test]
    fn supports_http_and_tls_search_fields() {
        let sql =
            parse_and_compile("title ~ camera AND http.body ~ hikvision AND tls.subject ~ example")
                .expect("new searchable fields should compile");
        assert!(sql.sql.contains("result.title ILIKE"));
        assert!(sql.sql.contains("result.http_body ILIKE"));
        assert!(sql.sql.contains("result.tls_subject ILIKE"));
    }

    #[test]
    fn documented_queries_compile() {
        let queries = [
            "ip IN 192.0.2.0/24 AND port IN (80, 443) AND service ~ \"http\" AND tag = \"生产环境\"",
            "country = CN AND service = \"https\" AND last_seen >= now-7d",
            "(country = CN OR country = SG) AND port = 443",
            "asn IN (4134, AS4837)",
            "ip = 2001:db8::10",
            "EXISTS(service) AND NOT EXISTS(banner)",
            "tag = \"公网\" AND tag = \"核心资产\"",
            "tag.kind IN (malicious, info)",
            "port = 80 AND has_endpoint(port = 443 AND service = \"https\")",
            "scanner ~ \"上海\" AND port = 443",
            "last_seen >= \"2026-08-01T00:00:00+08:00\"",
            "service IN (mysql, postgresql, mongodb, redis) OR port IN (3306, 5432, 27017, 6379)",
        ];

        for query in queries {
            parse_and_compile(query).unwrap_or_else(|error| {
                panic!("documented query failed: {query}: {}", error.message)
            });
        }
    }
}
