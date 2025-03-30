import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
  name: 'currencyFormat'
})
export class CurrencyFormatPipe implements PipeTransform {

  transform(value: number): string {
    const formatter = new Intl.NumberFormat('en-ZA', {
      style: 'currency',
      currency: 'ZAR',
      minimumFractionDigits: 0,
      maximumFractionDigits: 0,
      useGrouping: true,
    });

    const parts = formatter.formatToParts(value);
    const formattedValue = parts.map(part => {
      if (part.type === 'group') {
        return ' ';
      }
      return part.value;
    }).join('');

    return formattedValue.replace('R', 'R ');
  }

}