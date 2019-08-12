import React from 'react'
import { storiesOf } from '@storybook/react'
import { withViewport } from '@storybook/addon-viewport'

import ColumnsGrid from '../index'

storiesOf(`ColumnsGrid`, module)
  .addDecorator(withViewport())
  .addWithJSX(`Two columns: default`, () => (
    <ColumnsGrid columns={2}>
      <p>Column 1</p>
      <p>Column 2</p>
    </ColumnsGrid>
  ))
  .add(
    'Two columns: tablet',
    () => (
      <ColumnsGrid columns={2}>
        <p>Column 1</p>
        <p>Column 2</p>
      </ColumnsGrid>
    ),
    {
      viewport: 'ipad',
    }
  )
  .add(
    'Two columns: mobile',
    () => (
      <ColumnsGrid columns={2}>
        <p>Column 1</p>
        <p>Column 2</p>
      </ColumnsGrid>
    ),
    {
      viewport: 'iphone8p',
    }
  )
  .addWithJSX(`Three columns: default`, () => (
    <ColumnsGrid columns={3}>
      <p>Column 1</p>
      <p>Column 2</p>
      <p>Column 3</p>
    </ColumnsGrid>
  ))
  .add(
    'Three columns: tablet',
    () => (
      <ColumnsGrid columns={3}>
        <p>Column 1</p>
        <p>Column 2</p>
        <p>Column 3</p>
      </ColumnsGrid>
    ),
    {
      viewport: 'ipad',
    }
  )
  .add(
    'Three columns: mobile',
    () => (
      <ColumnsGrid columns={3}>
        <p>Column 1</p>
        <p>Column 2</p>
        <p>Column 3</p>
      </ColumnsGrid>
    ),
    {
      viewport: 'iphone8p',
    }
  )
