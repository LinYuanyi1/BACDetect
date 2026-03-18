import tree_sitter_java as tsjava
from tree_sitter import Language, Parser

# 1. 设置 Java 解析器
JAVA_LANGUAGE = Language(tsjava.language())
parser = Parser(JAVA_LANGUAGE)
# parser.set_language(JAVA_LANGUAGE)

# 2. 待分析的 Java 代码
java_code = """
package com.example;

import java.util.List;

public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
        return ;
    }
}
"""

# 3. 解析代码生成 AST
tree = parser.parse(bytes(java_code, "utf8"))
root_node = tree.root_node

# 4. 遍历节点示例 (查找方法名)
def get_method_names(node):
    if node.type == 'method_declaration':
        # 查找方法名节点
        for child in node.children:
            if child.type == 'identifier':
                print(f"找到方法: {child.text.decode('utf8')}")
    
    for child in node.children:
        get_method_names(child)

def text_of(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8")

# for children in root_node.children:
#     print(children)
print(root_node.children[0])

print("AST 结构分析：")
# get_method_names(root_node)
for child in root_node.children:
    if child.type == "package_declaration":
        scoped = None
        for sub in child.named_children:
            if sub.type == "scoped_identifier":
                scoped = sub
                break

        if scoped:
            scope_node = scoped.child_by_field_name("scope")
            name_node = scoped.child_by_field_name("name")

            print("scope =", text_of(scope_node, bytes(java_code, "utf8")))
            print("name =", text_of(name_node, bytes(java_code, "utf8")))