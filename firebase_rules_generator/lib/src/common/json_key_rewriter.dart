import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';
import 'package:analyzer/dart/element/element.dart';
import 'package:analyzer/dart/element/type.dart';

/// A utility function to rewrite JSON key names in an expression.
String toSourceWithJsonKeyReplacement(Expression expression) {
  final rewriter = JsonKeyRewriter();
  expression.accept(rewriter);
  return rewriter.rewrite(expression.toSource());
}

/// A visitor that visits property accesses and prefixed identifiers in the AST
/// and stores replacements for ones that have a `JsonKey` annotation.
///
/// Using `JsonKeyRewriter.rewrite` will apply the replacements to the original
/// source.
class JsonKeyRewriter extends RecursiveAstVisitor<void> {
  final Map<AstNode, String> _replacements = {};

  @override
  void visitPropertyAccess(PropertyAccess node) {
    _replaceIfJsonKey(node.target?.staticType, node.propertyName.name, node);
    super.visitPropertyAccess(node);
  }

  @override
  void visitPrefixedIdentifier(PrefixedIdentifier node) {
    _replaceIfJsonKey(node.prefix.staticType, node.identifier.name, node);
    super.visitPrefixedIdentifier(node);
  }

  void _replaceIfJsonKey(DartType? type, String fieldName, AstNode node) {
    if (type is! InterfaceType) return;

    for (final mixin in type.mixins) {
      final getter = mixin.getGetter(fieldName);
      if (getter == null) continue;

      final jsonKeyName = extractJsonKeyName(getter);

      if (jsonKeyName != null && jsonKeyName != fieldName) {
        _replacements[node] =
            node.toSource().replaceFirst(fieldName, jsonKeyName);
      }
    }
  }

  /// After visiting, apply the replacements
  String rewrite(String source) {
    var result = source;

    // Apply each replacement
    for (final replacement in _replacements.entries) {
      final node = replacement.key;
      final newValue = replacement.value;

      // Replace the node's source with the new value
      result = result.replaceFirst(node.toSource(), newValue);
    }

    return result.isEmpty ? source : result;
  }

  /// Copied helper from before
  String? extractJsonKeyName(Element element) {
    for (final annotation in element.metadata) {
      final value = annotation.computeConstantValue();
      if (value == null) continue;

      final type = value.type?.getDisplayString();
      if (type != 'JsonKey') continue;

      final nameField = value.getField('name');
      final nameValue = nameField?.toStringValue();

      if (nameValue != null && nameValue.isNotEmpty) {
        return nameValue;
      }
    }

    return null;
  }
}
