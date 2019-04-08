---
layout:     post
title:      MySQL 入门
subtitle:   SELECT
date:       2019-04-8
author:     qwqcxh
header-img: img/in-post/模板类壁纸/code-bg1.jpg
catalog: true
tags:
    - MySQL
    - 数据库
---

## MySQL DISTINCT
### Summary:
本节将使用DISTINCT 字句实现SELECT 结果的去重。

### introduction to MySQL DISTINCT clause
当从表中查询数据时，你可能会获得重复行，为了去除重复行，你应该使用`DISTINCT`子句。语法如下：
```
SELECT DISTINCT
    columns
FROM 
    table_name
WHERE 
    where_conditions;
```

### MySQL DISTINCT examples
首先，查询employees 表中 lastname列将出现重复的行。
```
SELECT 
    lastname
FROM 
    employees
ORDER BY lastname;
```
为了去除重复行，你可以在SELECT中加入DISTINCT 子句。
```
SELECT 
    DISTINCT lastname
FROM 
    employees
ORDER BY lastname;
```
**note** DISTINCT 会将多个NULL值的行当作重复行，因而最后只会保留一个NULL。

## 含有多列的DISTINCT
你可以对多个列使用DISTINCT子句，在这种情况下，MySQL会根据组合值进行去重。比如你想从customers表中获得具有唯一组合的city与state:
```
SELECT DISTINCT
    state,city
FROM 
    customers
WHERE 
    state IS NOT NULL
ORDER BY state,city;
```

## DISTINCT 子句与 GROUP BY 子句的区别
当你使用不带聚合函数的GROURP BY子句时，GROUP子句的行为与DISTINCT很类似，唯一的区别是GROUP BY的输出是按序的，而DISTINCT的输出是按照在原表的顺序输出。下面的两种写法是等价的：
```
SELECT 
    state
FROM 
    customers
GOUP BY state;
/*一种等价写法*/
SELECT DISTINCT
    state
FROM 
    customers
ORDER BY state;
```

## LIMIT 用法
LIMIT 用于控制输出行数。有两种语法：
`LIMIT lines`

`LIMIT offset,lines`
第一种用法将结果集的前lines行输出，第二种用法将从offset行开始的后lines行输出。举例如下：
```
SELECT DISTINCT
    state
FROM customers
WHERE 
    state IS NOT NULL
LIMIT 5;
```
这将输出customers表中state列非NULL的5行。