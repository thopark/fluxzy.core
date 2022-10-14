import { Component, OnInit } from '@angular/core';
import { MethodFilter, HostFilter } from '../../../../core/models/auto-generated';
import {
    IValidationSource,
    ValidationTargetComponent,
} from '../../filter-edit/filter-edit.component';

@Component({
    selector: 'app-host-filter-form',
    templateUrl: './host-filter-form.component.html',
    styleUrls: ['./host-filter-form.component.scss'],
})
export class HostFilterFormComponent extends ValidationTargetComponent<HostFilter>
    implements OnInit
{
    constructor() {
      super();
    }

    public filterInit(): void {
    }


    public validate(): string | null{
        if (!this.filter.pattern)
          {return 'Host cannot be empty';}

        return '';
    }
}
