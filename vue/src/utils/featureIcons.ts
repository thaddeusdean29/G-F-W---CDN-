import type { Component } from 'vue'
import {
  Aim, Cloudy, Coin, Compass, Connection, Cpu, DataLine, Guide, Histogram, Key, Lightning, Link,
  Location, Lock, Medal, Monitor, Odometer, Position, Promotion, Service, Star, Stopwatch, Timer, Trophy,
} from '@element-plus/icons-vue'

// 登录页功能卡片可选的图标。名字必须和后端 internal/apiv2/platform_settings.go 的 loginFeatureIcons 一致。
export const featureIcons: Record<string, Component> = {
  Connection, Lightning, Lock, DataLine, Monitor, Cloudy, Timer, Odometer,
  Histogram, Key, Promotion, Aim, Compass, Cpu, Position, Guide,
  Medal, Trophy, Service, Location, Link, Coin, Stopwatch, Star,
}

export const featureIconNames = Object.keys(featureIcons)
