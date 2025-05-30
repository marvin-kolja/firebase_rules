import 'package:analyzer/dart/ast/ast.dart';
import 'package:firebase_rules_generator/src/common/json_key_rewriter.dart';
import 'package:firebase_rules_generator/src/common/rules_context.dart';
import 'package:firebase_rules_generator/src/common/util.dart';

/// Visit Rule nodes
Stream<String> visitRule(RulesContext context, AstNode node) async* {
  final arguments =
      node.childEntities.whereType<ArgumentList>().single.arguments;
  final operationIdentifiers = arguments[0] as ListLiteral;
  final operations = operationIdentifiers.elements
      .cast<PrefixedIdentifier>()
      .map((e) => e.identifier.name);
  final conditionExpr = arguments[1];
  final condition = toSourceWithJsonKeyReplacement(conditionExpr);

  yield 'allow ${operations.join(', ')}: if $condition;'.indent(context.indent);
}
